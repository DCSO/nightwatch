// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DCSO/nightwatch/util"

	"github.com/NeowayLabs/wabbit/amqptest/server"
	"github.com/jarcoal/httpmock"
)

func fileContains(filename string, text string) (int, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	s := string(b)
	return strings.Count(s, text), nil
}

func checkFileContains(t *testing.T, filename string, text string) int {
	i := 0
	time.Sleep(5 * time.Second)
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Fatalf("expected file %s does not exist", filename)
	}
	val, err := fileContains(filename, text)
	if err != nil {
		t.Fatal(err)
	}
	for val == 0 {
		time.Sleep(5 * time.Second)
		val, err = fileContains(filename, text)
		if err != nil {
			t.Fatal(err)
		}
		if i > 5 {
			t.Fatalf("number of retries exceeded waiting for %s in %s", text, filename)
		}
		i++
	}
	return val
}

func TestMainFunc(t *testing.T) {
	serverURL := "amqp://sensor:sensor@localhost:9999/%2f/"
	yaraURL := "https://localhost:9998/test.yac"
	flag.Set("rule-uri", yaraURL)

	// start mock AMQP server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()
	defer fakeServer.Stop()

	// make sample YARA rules
	err := util.MakeYARARuleFile("../../testdata/test.yac")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("../../testdata/test.yac")

	// prepare and start mock HTTP server with rules
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	testYacFile, err := os.ReadFile("../../testdata/test.yac")
	if err != nil {
		t.Fatal(err)
	}
	httpmock.RegisterResponder("GET", "https://localhost:9998/test.yac",
		httpmock.NewBytesResponder(200, testYacFile))

	stopped := make(chan bool)

	// make test directory
	tdir, err := os.MkdirTemp("", "tdir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tdir)
	os.MkdirAll(filepath.Join(tdir, "testpath", "files"), 0755)

	// Run test wrapper for main()
	go testWrapper(filepath.Join(tdir, "testpath"), stopped)

	// Wait for first startup to settle
	time.Sleep(5 * time.Second)
	logfilename := filepath.Join(tdir, "testpath", "nightwatch.log")
	if checkFileContains(t, logfilename, "plugins successfully initialized") != 1 {
		t.Fatal("expected one initialization entry in logfile but couldn't find it")
	}

	// send HUP, check if plugins are reinitialized
	sigChan <- syscall.SIGHUP
	checkFileContains(t, logfilename, "SIGHUP")
	if checkFileContains(t, logfilename, "plugins successfully initialized") != 2 {
		t.Fatal("expected two initialization entries in logfile but couldn't find them")
	}

	// send USR1, check if rescan has been triggered
	sigChan <- syscall.SIGUSR1
	checkFileContains(t, logfilename, "SIGUSR1")
	if checkFileContains(t, logfilename, "rescanning") != 1 {
		t.Fatal("expected rescan notice in logfile but couldn't find it")
	}

	sigChan <- syscall.SIGTERM
	<-stopped
}
