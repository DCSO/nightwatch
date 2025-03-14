// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package uploader

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"

	"github.com/DCSO/nightwatch/sampledb"
	"github.com/DCSO/nightwatch/submitter"

	"github.com/minio/minio-go"
	log "github.com/sirupsen/logrus"
)

// S3Credentials represents a set of data required to access an S3 resource.
type S3Credentials struct {
	Endpoint        string
	AccessKey       string
	SecretAccessKey string
	BucketName      string
	Region          string
}

// UploadJob contains all data required to locate a file to be uploaded and its metadata.
type UploadJob struct {
	verdict          sampledb.FileVerdict
	localFilePath    string
	localVerdictPath string
}

// Uploader is a component that facilitates the queued upload of samples to a
// S3 endpoint, for example for later inspection.
type Uploader struct {
	// Creds contains the required credentials for the S3 connection.
	Creds S3Credentials
	// UseSSL is true if SSL should be used for upload.
	UseSSL bool
	// Where Suricata stores its extracted files.
	FileBaseDir string
	// Where the uploader queues files ready for upload.
	ScratchDir string
	// InChan is the channel to enqueue files for upload.
	InChan chan UploadJob
	// CloseChan is used to signal uploader shutdown.
	ClosedChan chan bool
	// Client is a Minio client connecting to the given endpoint.
	Client *minio.Client
	// Submitter is used to send verdicts after upload
	Submitter submitter.Submitter
}

// Enqueue adds a new file to the set of files to be uploaded. It also records the metadata
// given by the verdict.
func (u *Uploader) Enqueue(verdict sampledb.FileVerdict, localpath string) error {
	srcFile, err := os.Open(localpath)
	if err != nil {
		return err
	}

	destPath := path.Join(u.ScratchDir, verdict.Hashes.Sha512)
	destFile, err := os.Create(destPath)
	if err != nil {
		srcFile.Close()
		return err
	}

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		srcFile.Close()
		destFile.Close()
		return err
	}

	err = destFile.Sync()
	if err != nil {
		srcFile.Close()
		destFile.Close()
		return err
	}

	srcFile.Close()
	destFile.Close()

	var outJSON []byte
	verdictPath := path.Join(u.ScratchDir, fmt.Sprintf("%s.verdict.json", verdict.Hashes.Sha512))
	outJSON, err = json.Marshal(verdict)
	if err != nil {
		return err
	}
	err = os.WriteFile(verdictPath, outJSON, 0644)
	if err != nil {
		return err
	}

	u.InChan <- UploadJob{
		verdict:          verdict,
		localFilePath:    destPath,
		localVerdictPath: verdictPath,
	}
	return nil
}

func (u *Uploader) processUpload() {
	for file := range u.InChan {
		verdictFileName := fmt.Sprintf("%s.verdict.json", file.verdict.Hashes.Sha512)
		sampleFileName := file.verdict.Hashes.Sha512

		// upload sample
		log.Debugf("bucket %s object '%s' localpath %s", u.Creds.BucketName, sampleFileName,
			file.localFilePath)
		size, err := u.Client.FPutObject(u.Creds.BucketName, sampleFileName,
			file.localFilePath, minio.PutObjectOptions{
				ContentType: "application/octet-stream",
			})
		if err != nil {
			log.Errorf("upload of %s failed: %s ", sampleFileName, err)
			continue
		} else {
			log.Infof("successfully uploaded %s (size %d)", sampleFileName, size)
		}

		// upload verdict JSON
		log.Infof("bucket %s object '%s' localpath %s", u.Creds.BucketName, verdictFileName,
			file.localVerdictPath)
		size, err = u.Client.FPutObject(u.Creds.BucketName, verdictFileName,
			file.localVerdictPath, minio.PutObjectOptions{
				ContentType: "application/json",
			})
		if err != nil {
			log.Errorf("upload of %s failed: %s ", verdictFileName, err)
			continue
		} else {
			log.Infof("successfully uploaded %s (size %d)", verdictFileName, size)
			err = os.Remove(file.localFilePath)
			if err != nil {
				log.Errorf("could not remove uploaded file %s: %s", file.localFilePath, err)
			}
			err = os.Remove(file.localVerdictPath)
			if err != nil {
				log.Errorf("could not remove uploaded file %s: %s", file.localVerdictPath, err)
			}
		}

		// submit JSON with added location of sample
		file.verdict.Uploaded = true
		file.verdict.UploadLocation = fmt.Sprintf("%s/%s/%s", u.Creds.Endpoint, u.Creds.BucketName, file.verdict.Hashes.Sha512)
		if u.Submitter != nil {
			var submitJSON []byte
			submitJSON, err = json.Marshal(file.verdict)
			if err != nil {
				log.Error(err)
			} else {
				u.Submitter.Submit(submitJSON)
			}
		}
	}
	close(u.ClosedChan)
}

func (u *Uploader) enqueueBacklog() error {
	re := regexp.MustCompile(`.+\.verdict\.json$`)
	files, err := os.ReadDir(u.ScratchDir)
	if err != nil {
		return err
	}

	for _, f := range files {
		if re.Match([]byte(f.Name())) {
			var verdict sampledb.FileVerdict
			jsonFile, err := os.Open(path.Join(u.ScratchDir, f.Name()))
			if err != nil {
				return err
			}
			byteValue, _ := io.ReadAll(jsonFile)
			jsonFile.Close()
			err = json.Unmarshal(byteValue, &verdict)
			if err != nil {
				return err
			}
			fi, err := f.Info()
			var size = 0
			if err != nil {
				size = int(fi.Size())
			}
			log.Debugf("enqueuing scratch file %s, %d bytes", f.Name(), size)
			u.InChan <- UploadJob{
				verdict:          verdict,
				localFilePath:    path.Join(u.ScratchDir, verdict.Hashes.Sha512),
				localVerdictPath: path.Join(u.ScratchDir, f.Name()),
			}
		}
	}

	return nil
}

// MakeS3Uploader returns a new Uploader for the given credentials and environment settings.
// If a submitter is given, it will be used to submit the verdict metadata for each queued
// file as well.
func MakeS3Uploader(creds S3Credentials, ssl bool, basedir string, scratchdir string,
	submitter submitter.Submitter) (*Uploader, error) {
	uploader := &Uploader{
		Creds:       creds,
		UseSSL:      ssl,
		FileBaseDir: basedir,
		ScratchDir:  scratchdir,
		ClosedChan:  make(chan bool),
		InChan:      make(chan UploadJob, 10000),
		Submitter:   submitter,
	}

	client, err := minio.New(creds.Endpoint, creds.AccessKey, creds.SecretAccessKey, ssl)
	if err != nil {
		return nil, err
	}
	uploader.Client = client

	err = uploader.enqueueBacklog()
	if err != nil {
		return nil, err
	}

	go uploader.processUpload()

	return uploader, nil
}

// Stop causes the uploader to cease processing enqueued files.
func (u *Uploader) Stop() {
	close(u.InChan)
	<-u.ClosedChan
}
