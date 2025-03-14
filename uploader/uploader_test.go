// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package uploader

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DCSO/nightwatch/sampledb"
	"github.com/DCSO/nightwatch/submitter"
	"github.com/DCSO/nightwatch/util"
)

var regionReturn = `
<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">TEST</LocationConstraint>
`

func TestUpload(t *testing.T) {
	hasFile := false
	hasVerdict := false

	s := submitter.MakeDummySubmitter()

	var apiStub = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		if strings.Contains(r.URL.String(), "12345.verdict.json") {
			w.WriteHeader(http.StatusOK)
			if !strings.Contains(string(buf), "Suspicious") {
				t.Fatal("incomplete verdict")
			} else {
				hasVerdict = true
			}
		} else if strings.Contains(r.URL.String(), "12345") {
			w.WriteHeader(http.StatusOK)
			if string(buf) != "foo bar2" {
				t.Fatal("no file")
			} else {
				hasFile = true
			}
		} else if strings.Contains(r.URL.String(), "location") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(regionReturn))
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer apiStub.Close()

	indir, err := os.MkdirTemp("", "indir")
	if err != nil {
		t.Fatal(err)
	}

	scratchdir, err := os.MkdirTemp("", "scratchdir")
	if err != nil {
		os.RemoveAll(indir)
		t.Fatal(err)
	}

	u, err := MakeS3Uploader(S3Credentials{
		Endpoint:   strings.Replace(apiStub.URL, "http://", "", -1),
		BucketName: "incoming",
		Region:     "TEST",
	}, false, indir, scratchdir, s)
	if err != nil {
		os.RemoveAll(indir)
		os.RemoveAll(scratchdir)
		t.Fatal(err)
	}

	util.CreateFilePair(2, []byte("foo bar2"), 10, indir)

	var reasons map[string]interface{}
	err = json.Unmarshal([]byte(`{"test": "foobar"}`), &reasons)
	if err != nil {
		os.RemoveAll(indir)
		os.RemoveAll(scratchdir)
		t.Fatal(err)
	}
	u.Enqueue(sampledb.FileVerdict{
		Hashes: sampledb.HashInfo{
			Sha512: "12345",
		},
		Suspicious:    true,
		SuspiciousVia: []string{"test"},
		Reasons:       reasons,
		Filename:      "file.2",
		Size:          8,
	}, filepath.Join(indir, "file.2"))

	u.Stop()

	os.RemoveAll(indir)
	os.RemoveAll(scratchdir)

	if !hasFile || !hasVerdict {
		t.Fatal("no complete set of file and verdict")
	}
}

func TestUploaderBacklog(t *testing.T) {
	hasFile := false
	hasVerdict := false

	s := submitter.MakeDummySubmitter()

	var apiStub = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		if strings.Contains(r.URL.String(), "12345.verdict.json") {
			w.WriteHeader(http.StatusOK)
			if !strings.Contains(string(buf), "Suspicious") {
				t.Fatal("incomplete verdict")
			} else {
				hasVerdict = true
			}
		} else if strings.Contains(r.URL.String(), "12345") {
			w.WriteHeader(http.StatusOK)
			if string(buf) != "foo bar2" {
				t.Fatal("no file")
			} else {
				hasFile = true
			}
		} else if strings.Contains(r.URL.String(), "location") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(regionReturn))
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer apiStub.Close()

	indir, err := os.MkdirTemp("", "indir")
	if err != nil {
		t.Fatal(err)
	}

	scratchdir, err := os.MkdirTemp("", "scratchdir")
	if err != nil {
		os.RemoveAll(indir)
		t.Fatal(err)
	}

	var reasons map[string]interface{}
	err = json.Unmarshal([]byte(`{"test": "foobar"}`), &reasons)
	if err != nil {
		os.RemoveAll(indir)
		os.RemoveAll(scratchdir)
		t.Fatal(err)
	}

	fv := sampledb.FileVerdict{
		Hashes: sampledb.HashInfo{
			Sha512: "12345",
		},
		Suspicious:    true,
		SuspiciousVia: []string{"test"},
		Reasons:       reasons,
		Filename:      "file.2",
		Size:          8,
	}
	verdictJSON, _ := json.Marshal(fv)
	os.WriteFile(filepath.Join(scratchdir, "12345.verdict.json"), verdictJSON, 0644)
	os.WriteFile(filepath.Join(scratchdir, "12345"), []byte("foo bar2"), 0644)

	u, err := MakeS3Uploader(S3Credentials{
		Endpoint:   strings.Replace(apiStub.URL, "http://", "", -1),
		BucketName: "incoming",
		Region:     "TEST",
	}, false, indir, scratchdir, s)
	if err != nil {
		os.RemoveAll(indir)
		os.RemoveAll(scratchdir)
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	u.Stop()

	os.RemoveAll(indir)
	os.RemoveAll(scratchdir)

	if !hasFile || !hasVerdict {
		t.Fatal("no complete set of file and verdict")
	}
}
