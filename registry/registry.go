// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

// Package registry - Reference: http://stackoverflow.com/questions/28001872/golang-events-eventemitter-dispatcher-for-plugin-architecture
package registry

import (
	"encoding/json"
	"flag"
	"os"
	"time"

	"github.com/DCSO/nightwatch/sampledb"
	"github.com/DCSO/nightwatch/submitter"
	"github.com/DCSO/nightwatch/uploader"

	log "github.com/sirupsen/logrus"
)

var rescanTimeframe = flag.Duration("rescantime", time.Hour*72, "rescan files older than time period")

// PluginIterator opens a given sample file and processes it with all registered
// plugins.
func PluginIterator(fiev sampledb.FileInfoEvent, s submitter.Submitter, uploader *uploader.Uploader) error {
	var verdict sampledb.FileVerdict
	verdict.Reasons = make(map[string]interface{})
	verdict.SuspiciousVia = make([]string, 0)

	sample, err := os.Open(fiev.FilePath)
	if err != nil {
		return err
	}
	defer sample.Close()

	sampleStat, err := sample.Stat()
	if err != nil {
		return err
	}

	hashes, err := CalculateBasicHashes(sample)
	if err != nil {
		return err
	}

	se, err := sampledb.GetSampleEntry(hashes.Sha512)
	if err != nil && err.Error() != "missing bucket" {
		return err
	}

	// If the result set is empty this is a new sample and we process it if it has
	// not been scanned in rescanTimeframe otherwise return.
	if se.Hashes.Sha512 != "" && time.Now().UTC().Sub(se.Time) < *rescanTimeframe {
		log.Debug("sample already processed: ", fiev.FilePath)
		return err
	}

	// Iterate over the available plugins and let them do their analysis. If they
	// find something suspicious they should return a non empty Reason struct.
	var suspicious = false
	for _, plug := range AnalysisPlugins {
		output, pluginSuspicious, anaErr := plug.ProcessFile(FileSample{
			FD:       sample.Fd(),
			Info:     sampleStat,
			OrigPath: fiev.FilePath,
		})
		if anaErr != nil {
			log.Errorf("plugin (%s) error processing file: %s", plug.Name(), anaErr)
			continue
		}

		if output != "" {
			var result interface{}
			anaErr = json.Unmarshal([]byte(output), &result)
			if anaErr != nil {
				log.Errorf("error in plugin return data %v %v", plug.Name(), err)
				continue
			}
			verdict.Reasons[plug.Name()] = result
		}
		if !suspicious {
			suspicious = pluginSuspicious
		}
		if pluginSuspicious {
			verdict.SuspiciousVia = append(verdict.SuspiciousVia, plug.Name())
		}
	}
	verdict.Suspicious = suspicious
	verdict.Filename = fiev.FilePath
	verdict.Time = time.Now().UTC()
	verdict.CollectionTime = sampleStat.ModTime().UTC()
	verdict.SensorID = submitter.SensorID
	verdict.Size = sampleStat.Size()
	verdict.Hashes = hashes
	verdict.Magic = MagicFromFile(fiev.FilePath)
	verdict.Metadata = fiev.JSONMessage

	err = sampledb.CreateSampleEntry(verdict)
	if err != nil {
		return err
	}

	metaFile := fiev.FilePath + ".meta"
	if _, err = os.Stat(metaFile); err == nil {
		content, fileErr := os.ReadFile(metaFile)
		if fileErr != nil {
			return fileErr
		}
		verdict.MetaFile = content
	} else {
		log.Debug("metafile not found: ", metaFile)
	}

	// Marshal the verdict struct as JSON...
	msg, err := json.Marshal(verdict)
	if err != nil {
		return err
	}

	/// and send it on (and the file possibly as well)
	if uploader != nil {
		if verdict.Suspicious {
			// in this case the uploader will handle submitting the verdict
			// after adding the uploaded file location
			err = uploader.Enqueue(verdict, fiev.FilePath)
			if err != nil {
				return err
			}
		} else {
			err = s.Submit(msg)
			if err != nil {
				return err
			}
		}
	} else {
		err = s.Submit(msg)
		if err != nil {
			return err
		}
	}
	verdict.Reported = true

	// Update the sample entry in the DB with our new information
	err = sampledb.CreateSampleEntry(verdict)
	return err
}
