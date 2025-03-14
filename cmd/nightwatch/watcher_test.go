// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DCSO/nightwatch/registry"
	"github.com/DCSO/nightwatch/sampledb"
	"github.com/DCSO/nightwatch/submitter"
	"github.com/DCSO/nightwatch/util"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqptest"
	"github.com/NeowayLabs/wabbit/amqptest/server"
	"github.com/buger/jsonparser"
	"github.com/jarcoal/httpmock"
	log "github.com/sirupsen/logrus"
)

func _TestBacklog(t *testing.T, version int) {
	serverURL := "amqp://sensor:sensor@localhost:9999/%2f/"
	yaraURL := "https://localhost:9998/test.yac"
	flag.Set("rule-uri", yaraURL)

	// make sample YARA rules
	err := util.MakeYARARuleFile("../../testdata/test.yac")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("../../testdata/test.yac")

	// start mock AMQP server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()
	defer fakeServer.Stop()

	// prepare and start mock HTTP server with rules
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	testYacFile, err := os.ReadFile("../../testdata/test.yac")
	if err != nil {
		t.Fatal(err)
	}
	httpmock.RegisterResponder("GET", "https://localhost:9998/test.yac",
		httpmock.NewBytesResponder(200, testYacFile))

	// set up consumer and track suspicious files
	suspicious := make(map[string]bool)
	var smu sync.RWMutex
	c, err := submitter.NewConsumer(serverURL, "nightwatch", "direct", "test",
		"nightwatch", "nightwatch-test", func(d wabbit.Delivery) {
			status, myerr := jsonparser.GetBoolean(d.Body(), "Suspicious")
			if myerr != nil {
				t.Error(myerr)
			}
			filename, myerr := jsonparser.GetString(d.Body(), "Filename")
			if myerr != nil {
				t.Error(myerr)
			}
			smu.Lock()
			suspicious[filename] = status
			smu.Unlock()
		})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()

	// set up submitter
	s, err := submitter.MakeAMQPSubmitterWithReconnector("localhost:9999/%2f", "sensor",
		"sensor", "nightwatch", true, func(url string) (wabbit.Conn, string, error) {
			// we pass in a custom reconnector which uses the amqptest implementation
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, "direct", err
		})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Finish()

	// Setup database connection and create the database file if not exist
	dbdir, err := os.MkdirTemp("", "dbdir")
	if err != nil {
		log.Fatal(err)
	}
	err = sampledb.InitDB(dbdir)
	if err != nil {
		log.Fatal(err)
	}
	defer sampledb.CloseDB()
	defer os.RemoveAll(dbdir)

	// Initialize plugins and call their Initialize functions to give them a chance
	// to prepare their matching engines.
	for n, d := range registry.AnalysisPlugins {
		err = d.ReInitialize()
		if err != nil {
			log.Fatalf("Error initializing plugin [%v]: %v", n, err)
		}
	}

	// Create example directory
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	tinybytes, err := os.ReadFile(filepath.Join("testdata", "tiny.exe"))
	if err != nil {
		t.Fatal(err)
	}

	// Spawn some file pairs (like binary and metafile)
	if version == 1 {
		util.CreateFilePair(1, tinybytes, 100, dir)
		util.CreateFilePair(2, append(tinybytes, []byte("foo bar2")...), 100, dir)
		util.CreateFilePair(3, tinybytes, 100, dir)
		util.CreateFilePair(4, tinybytes, 100, dir)
	} else {
		util.CreateFilePairV2(1, tinybytes, 100, dir)
		util.CreateFilePairV2(2, append(tinybytes, []byte("foo bar2")...), 100, dir)
		util.CreateFilePairV2(3, tinybytes, 100, dir)
		util.CreateFilePairV2(4, tinybytes, 100, dir)
	}

	w := MakeWatcher(nil, s, nil)
	defer w.Finish()
	w.backlogBuilder(dir, s, version)

	smu.Lock()

	if version == 1 {
		if len(suspicious) != 4 {
			t.Fail()
		}
		if !suspicious[filepath.Join(dir, "file.2")] {
			t.Fatal("file.2 wasn't marked as suspicious but should be")
		}
		if suspicious[filepath.Join(dir, "file.1")] {
			t.Fatal("file.1 was marked as suspicious but shouldn't")
		}
		if suspicious[filepath.Join(dir, "file.3")] {
			t.Fatal("file.3 was marked as suspicious but shouldn't")
		}
		if suspicious[filepath.Join(dir, "file.4")] {
			t.Fatal("file.4 was marked as suspicious but shouldn't")
		}
	} else {
		if len(suspicious) != 2 {
			t.Fail()
		}
		log.Info(suspicious)
		if !suspicious[filepath.Join(dir, "8d", "8d44bf792760af5a9e04a65f6b9fb366c98d923d54ed30fd05212f012eb03a58")] {
			t.Fatal("file wasn't marked as suspicious but should be")
		}
		if suspicious[filepath.Join(dir, "55", "55cfd3bcea1aa352b4687c4d45bdcfea184ce9b58320891a2d72d4ec93766f14")] {
			t.Fatal("file was marked as suspicious but shouldn't")
		}
	}
	smu.Unlock()
}

func TestBacklogV1(t *testing.T) {
	_TestBacklog(t, 1)
}

func TestBacklogV2(t *testing.T) {
	_TestBacklog(t, 2)
}

const (
	fileinfoStr = "{\"timestamp\":\"2017-03-06T09:03:48.355600+0000\",\"event_type\":\"fileinfo\",\"fileinfo\":{\"filename\":\"foo\",\"state\":\"CLOSED\",\"stored\":true,\"file_id\":%v,\"size\":0,\"magic\":\"PE32 executable (GUI) Intel 80386, for MS Windows\"}}\n"
)

func TestSubmitter(t *testing.T) {
	serverURL := "amqp://sensor:sensor@localhost:9999/%2f/"
	yaraURL := "https://localhost:9998/test.yac"
	flag.Set("rule-uri", yaraURL)

	// make sample YARA rules
	err := util.MakeYARARuleFile("../../testdata/test.yac")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("../../testdata/test.yac")

	// start mock AMQP server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()
	defer fakeServer.Stop()

	dir, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	tmpfn := filepath.Join(dir, fmt.Sprintf("t%d", rand.Int63()))

	// prepare and start mock HTTP server with rules
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	testYacFile, err := os.ReadFile("../../testdata/test.yac")
	if err != nil {
		t.Fatal(err)
	}
	httpmock.RegisterResponder("GET", "https://localhost:9998/test.yac",
		httpmock.NewBytesResponder(200, testYacFile))

	// set up consumer
	suspicious := make(map[string]bool)
	var smu sync.RWMutex
	c, err := submitter.NewConsumer(serverURL, "nightwatch", "direct", "test2",
		"nightwatch", "nightwatch-test", func(d wabbit.Delivery) {
			status, myerr := jsonparser.GetBoolean(d.Body(), "Suspicious")
			if myerr != nil {
				t.Error(myerr)
			}
			filename, myerr := jsonparser.GetString(d.Body(), "Filename")
			if myerr != nil {
				t.Error(myerr)
			}
			smu.Lock()
			suspicious[filename] = status
			smu.Unlock()
		})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Shutdown()

	// set up submitter
	s, err := submitter.MakeAMQPSubmitterWithReconnector("localhost:9999/%2f", "sensor",
		"sensor", "nightwatch", true, func(url string) (wabbit.Conn, string, error) {
			// we pass in a custom reconnector which uses the amqptest implementation
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, "direct", err
		})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Finish()

	// Setup database connection and create the database file if not exist
	dbdir, err := os.MkdirTemp("", "dbdir")
	if err != nil {
		log.Fatal(err)
	}
	err = sampledb.InitDB(dbdir)
	if err != nil {
		log.Fatal(err)
	}
	defer sampledb.CloseDB()
	defer os.RemoveAll(dbdir)

	// Initialize plugins and call their Initialize functions to give them a chance
	// to prepare their matching engines.
	for n, d := range registry.AnalysisPlugins {
		err = d.ReInitialize()
		if err != nil {
			log.Fatalf("Error initializing plugin [%v]: %v", n, err)
		}
	}

	// Create example directory
	dir, err = os.MkdirTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Watch directory
	finishNotify := make(chan bool)
	w := MakeWatcher(finishNotify, s, nil)
	defer w.Finish()
	w.Run(dir, 1, tmpfn)

	tinybytes, err := os.ReadFile(filepath.Join("testdata", "tiny.exe"))
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("unix", tmpfn)
	if err != nil {
		log.Println(err)
	}

	// Spawn some file pairs (like binary and metafile)
	util.CreateFilePair(5, append(tinybytes, []byte("foo bar")...), 10, dir)
	conn.Write([]byte(fmt.Sprintf(fileinfoStr, 5)))
	util.CreateFilePair(6, append(tinybytes, []byte("foo bar2")...), 10, dir)
	conn.Write([]byte(fmt.Sprintf(fileinfoStr, 6)))
	util.CreateFilePair(7, append(tinybytes, []byte("foo bar3")...), 10, dir)
	conn.Write([]byte(fmt.Sprintf(fileinfoStr, 7)))
	util.CreateFilePair(8, append(tinybytes, []byte(strings.Repeat("baa", 30000))...), 20000, dir)
	conn.Write([]byte(fmt.Sprintf(fileinfoStr, 8)))
	util.CreateFilePairMoved(9, append(tinybytes, []byte("foo bar5")...), dir)
	conn.Write([]byte(fmt.Sprintf(fileinfoStr, 9)))

	util.CreateFilePairMoved(10, append(tinybytes, []byte("foo bar6")...), dir)
	conn.Write([]byte(fmt.Sprintf(fileinfoStr, 10)))
	util.CreateFilePairMoved(11, append(tinybytes, []byte("foo bar6")...), dir) // duplicate file
	conn.Write([]byte(fmt.Sprintf(fileinfoStr, 11)))
	conn.Close()

	time.Sleep(10 * time.Second)

	// stop watcher
	w.Stop()

	// wait for watcher to finish and shut down
	<-finishNotify

	smu.Lock()
	if len(suspicious) != 6 {
		t.Fatal("expected 6 verdicts but got", len(suspicious))
	}
	if !suspicious[filepath.Join(dir, "file.6")] {
		t.Fatal("file.6 wasn't marked as suspicious but should be")
	}
	if suspicious[filepath.Join(dir, "file.5")] {
		t.Fatal("file.5 was marked as suspicious but shouldn't")
	}
	if suspicious[filepath.Join(dir, "file.7")] {
		t.Fatal("file.7 was marked as suspicious but shouldn't")
	}
	if suspicious[filepath.Join(dir, "file.8")] {
		t.Fatal("file.8 was marked as suspicious but shouldn't")
	}
	if suspicious[filepath.Join(dir, "file.9")] {
		t.Fatal("file.9 was marked as suspicious but shouldn't")
	}
	if suspicious[filepath.Join(dir, "file.10")] {
		t.Fatal("file.10 was marked as suspicious but shouldn't")
	}
	if _, ok := suspicious[filepath.Join(dir, "file.11")]; ok {
		t.Fatal("file.11 was inspected but should not have been")
	}
	smu.Unlock()
}

func _TestBacklogDelete(t *testing.T, version int) {
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	filename1 := filepath.Join(dir, "mystrangefile1")
	f, err := os.Create(filename1)
	if err != nil {
		log.Fatal(err)
	}
	f.Write([]byte("foobarbaz"))
	f.Close()

	os.MkdirAll(filepath.Join(dir, "ff"), os.ModePerm)
	filename2 := filepath.Join(dir, "ff", "mystrangefile2")
	f, err = os.Create(filename2)
	if err != nil {
		log.Fatal(err)
	}
	f.Write([]byte("foobarbaz"))
	f.Close()

	filename3 := filepath.Join(dir, "ff", "file.25")
	f, err = os.Create(filename3)
	if err != nil {
		log.Fatal(err)
	}
	f.Write([]byte("foobarbaz"))
	f.Close()

	filename4 := filepath.Join(dir, "ff", "file.25.meta")
	f, err = os.Create(filename4)
	if err != nil {
		log.Fatal(err)
	}
	f.Write([]byte("foobarbaz"))
	f.Close()

	filename5 := filepath.Join(dir, "ff", "ff53d10b98ae3d38384b30e4b6f63923d7d3a68b67e340cbda95ca22a5a6edbb")
	f, err = os.Create(filename5)
	if err != nil {
		log.Fatal(err)
	}
	f.Write([]byte("foobarbaz"))
	f.Close()

	filename6 := filepath.Join(dir, "ff", "ff53d10b98ae3d38384b30e4b6f63923d7d3a68b67e340cbda95ca22a5a6edbb.23423434.24234.json")
	f, err = os.Create(filename6)
	if err != nil {
		log.Fatal(err)
	}
	f.Write([]byte("foobarbaz"))
	f.Close()

	s := submitter.MakeDummySubmitter()

	w := MakeWatcher(nil, s, nil)
	w.FilestoreVersion, _ = intToStoreVersion(version)
	defer w.Finish()
	w.backlogBuilder(dir, s, version)

	if version == 1 {
		_, err = os.Stat(filename1)
		if err != nil && os.IsNotExist(err) {
			t.Fatalf("File is expected but actually missing: %s", filename1)
		}

		_, err = os.Stat(filename2)
		if err != nil && os.IsNotExist(err) {
			t.Fatalf("File is expected but actually missing: %s", filename2)
		}

		_, err = os.Stat(filename3)
		if err == nil || !os.IsNotExist(err) {
			t.Fatalf("File exists but should be missing: %s", filename3)
		}

		_, err = os.Stat(filename4)
		if err == nil || !os.IsNotExist(err) {
			t.Fatalf("File exists but should be missing: %s", filename4)
		}

		_, err = os.Stat(filename5)
		if err != nil && os.IsNotExist(err) {
			t.Fatalf("File is expected but actually missing: %s", filename5)
		}

		_, err = os.Stat(filename6)
		if err != nil && os.IsNotExist(err) {
			t.Fatalf("File is expected but actually missing: %s", filename6)
		}
	} else {
		_, err = os.Stat(filename1)
		if err != nil && os.IsNotExist(err) {
			t.Fatalf("File is expected but actually missing: %s", filename1)
		}

		_, err = os.Stat(filename2)
		if err != nil && os.IsNotExist(err) {
			t.Fatalf("File is expected but actually missing: %s", filename2)
		}

		_, err = os.Stat(filename5)
		if err == nil || !os.IsNotExist(err) {
			t.Fatalf("File exists but should be missing: %s", filename5)
		}

		_, err = os.Stat(filename6)
		if err == nil || !os.IsNotExist(err) {
			t.Fatalf("File exists but should be missing: %s", filename6)
		}

		_, err = os.Stat(filename3)
		if err != nil && os.IsNotExist(err) {
			t.Fatalf("File is expected but actually missing: %s", filename3)
		}

		_, err = os.Stat(filename4)
		if err != nil && os.IsNotExist(err) {
			t.Fatalf("File is expected but actually missing: %s", filename4)
		}
	}
}

func TestBacklogDeleteV1(t *testing.T) {
	_TestBacklogDelete(t, 1)
}

func TestBacklogDeleteV2(t *testing.T) {
	_TestBacklogDelete(t, 2)
}
