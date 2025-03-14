// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DCSO/nightwatch/util"
)

func TestJanitorAge(t *testing.T) {
	// Create example directory
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Spawn some file pairs (like binary and metafile)
	util.CreateFilePairWithTime(1, []byte("foo bar"), 10, dir, time.Now().AddDate(0, 0, -2))
	util.CreateFilePair(2, []byte("foo bar2"), 10, dir)
	util.CreateFilePair(3, []byte("foo bar3"), 10, dir)
	util.CreateFilePair(4, []byte(strings.Repeat("baa", 300000)), 20000, dir)

	// Watch directory
	finishNotify := make(chan bool)
	j := MakeJanitor(finishNotify)
	*MaxAge = 24 * time.Hour
	j.CheckTick = 5 * time.Second
	j.Run(dir)

	time.Sleep(7 * time.Second)

	// stop janitor
	j.Stop()

	if _, err := os.Stat(filepath.Join(dir, "file.1")); !os.IsNotExist(err) {
		t.Error("file.1 exists but should have been cleaned up")
	}
	if _, err := os.Stat(filepath.Join(dir, "file.2")); os.IsNotExist(err) {
		t.Error("file.2 is gone but should exist")
	}
	if _, err := os.Stat(filepath.Join(dir, "file.3")); os.IsNotExist(err) {
		t.Error("file.3 is gone but should exist")
	}
	if _, err := os.Stat(filepath.Join(dir, "file.4")); os.IsNotExist(err) {
		t.Error("file.4 is gone but should exist")
	}

	// wait for janitor to finish and shut down
	<-finishNotify
}

func TestJanitorSpace(t *testing.T) {
	// Create example directory
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Spawn some file pairs (like binary and metafile)
	util.CreateFilePair(1, []byte(strings.Repeat("baa", 300000)), 20000, dir)
	util.CreateFilePair(2, []byte(strings.Repeat("aba", 300000)), 20000, dir)
	util.CreateFilePair(3, []byte(strings.Repeat("bab", 300000)), 20000, dir)
	util.CreateFilePair(4, []byte(strings.Repeat("bba", 300000)), 20000, dir)
	util.CreateFilePair(5, []byte(strings.Repeat("bba", 300000)), 20000, dir)

	// Watch directory
	finishNotify := make(chan bool)
	j := MakeJanitor(finishNotify)
	*MaxSpace = 2
	j.CheckTick = 5 * time.Second
	j.Run(dir)

	time.Sleep(7 * time.Second)

	// stop janitor
	j.Stop()

	if _, err := os.Stat(filepath.Join(dir, "file.1")); !os.IsNotExist(err) {
		t.Error("file.1 exists but should have been cleaned up")
	}
	if _, err := os.Stat(filepath.Join(dir, "file.2")); !os.IsNotExist(err) {
		t.Error("file.2 exists but should have been cleaned up")
	}
	if _, err := os.Stat(filepath.Join(dir, "file.3")); !os.IsNotExist(err) {
		t.Error("file.3 is gone but should exist")
	}
	if _, err := os.Stat(filepath.Join(dir, "file.4")); os.IsNotExist(err) {
		t.Error("file.4 is gone but should exist")
	}
	if _, err := os.Stat(filepath.Join(dir, "file.5")); os.IsNotExist(err) {
		t.Error("file.5 is gone but should exist")
	}

	// wait for janitor to finish and shut down
	<-finishNotify
}
