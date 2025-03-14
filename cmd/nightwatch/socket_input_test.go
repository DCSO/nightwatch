// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/DCSO/nightwatch/sampledb"

	log "github.com/sirupsen/logrus"
)

func sendSocketMessage(_ *testing.T, msg socketMessage, socket string) {
	c, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	jsonBytes, err := json.Marshal(msg)
	if err != nil {
		log.Fatal(err)
	}
	log.Info(string(jsonBytes))
	c.Write(jsonBytes)
	c.Write([]byte("\n"))
	c.Close()
}
func TestSocketInputRegularV2(t *testing.T) {
	dir, err := os.MkdirTemp("", "test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	message1 := socketMessage{
		EventType: "fileinfo",
		FileInfo: socketMessageFileinfo{
			Filename: "foo",
			FileID:   23,
			Stored:   true,
			Magic:    "PE32 executable (GUI) Intel 80386, for MS Windows",
			Sha256:   "40c38478248ab915fc6d988b54860d0eec3f1e6ff3c968d65ff8d0840614382f",
		},
	}

	err = os.MkdirAll(filepath.Join(dir, "files", "40"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	baseFileName := filepath.Join(dir, "files", "40", message1.FileInfo.Sha256)
	err = os.WriteFile(baseFileName, []byte("123"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	metaFileName := fmt.Sprintf("%s.1547728944.1138003.json", baseFileName)
	err = os.WriteFile(metaFileName, []byte("123"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	fileEventChan := make(chan sampledb.FileInfoEvent)

	tmpfn := filepath.Join(dir, fmt.Sprintf("t%d", rand.Int63()))

	var wg sync.WaitGroup
	si, err := MakeSocketInput(tmpfn, fileEventChan, filepath.Join(dir, "files"), &wg, 2)
	if err != nil {
		t.Fatal(err)
	}

	receiveDone := make(chan bool)

	go sendSocketMessage(t, message1, tmpfn)

	events := make([]sampledb.FileInfoEvent, 0)
	go func(myWg *sync.WaitGroup) {
		fe := <-fileEventChan
		events = append(events, fe)
		myWg.Done()
		close(receiveDone)
	}(&wg)

	si.Run()
	wg.Wait()
	<-receiveDone

	if len(events) != 1 {
		t.Fatalf("wrong number of file events: %d", len(events))
	}
	if events[0].FilePath != filepath.Join(dir, "files", "40", message1.FileInfo.Sha256) {
		t.Fatalf("wrong file path: %s != %s", events[0].FilePath,
			filepath.Join(dir, "files", "40", message1.FileInfo.Sha256))
	}
	if _, err = os.Stat(baseFileName); os.IsNotExist(err) {
		t.Fatalf("deleted file by error")
	}
	if _, err = os.Stat(metaFileName); os.IsNotExist(err) {
		t.Fatalf("deleted metafile by error")
	}
}

func TestSocketInputNonInterestingV2(t *testing.T) {
	dir, err := os.MkdirTemp("", "test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	message1 := socketMessage{
		EventType: "fileinfo",
		FileInfo: socketMessageFileinfo{
			Filename: "foo",
			FileID:   23,
			Stored:   true,
			Magic:    "Zorgo-Boink V5",
			Sha256:   "40c38478248ab915fc6d988b54860d0eec3f1e6ff3c968d65ff8d0840614382f",
		},
	}

	err = os.MkdirAll(filepath.Join(dir, "files", "40"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	baseFileName := filepath.Join(dir, "files", "40", message1.FileInfo.Sha256)
	err = os.WriteFile(baseFileName, []byte("123"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	metaFile1Name := fmt.Sprintf("%s.1547728944.1138003.json", baseFileName)
	err = os.WriteFile(metaFile1Name, []byte("123"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	metaFile2Name := fmt.Sprintf("%s.1547728944.1138343.json", baseFileName)
	err = os.WriteFile(metaFile2Name, []byte("123"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	fileEventChan := make(chan sampledb.FileInfoEvent)

	tmpfn := filepath.Join(dir, fmt.Sprintf("t%d", rand.Int63()))

	var wg sync.WaitGroup
	si, err := MakeSocketInput(tmpfn, fileEventChan, filepath.Join(dir, "files"), &wg, 2)
	if err != nil {
		t.Fatal(err)
	}

	receiveDone := make(chan bool)

	go sendSocketMessage(t, message1, tmpfn)

	go func(myWg *sync.WaitGroup) {
		select {
		case <-fileEventChan:
			log.Fatal("expected no output from channel")
			myWg.Done()
		case <-time.After(5 * time.Second):
			// pass
		}

		close(receiveDone)
	}(&wg)

	si.Run()
	wg.Wait()
	<-receiveDone

	if _, err = os.Stat(baseFileName); os.IsExist(err) {
		t.Fatalf("file not deleted")
	}
	if _, err = os.Stat(metaFile1Name); os.IsExist(err) {
		t.Fatalf("metafile not deleted")
	}
	if _, err = os.Stat(metaFile2Name); os.IsExist(err) {
		t.Fatalf("metafile not deleted")
	}
}

func TestSocketInputBrokenV2(t *testing.T) {
	dir, err := os.MkdirTemp("", "test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	message1 := socketMessage{
		EventType: "fileinfo",
		FileInfo: socketMessageFileinfo{
			Filename: "/",
			FileID:   0,
			Stored:   true,
			Magic:    "ISO-8859 text, with very long lines",
			Sha256:   "",
		},
	}
	fileEventChan := make(chan sampledb.FileInfoEvent)

	tmpfn := filepath.Join(dir, fmt.Sprintf("t%d", rand.Int63()))

	var wg sync.WaitGroup
	si, err := MakeSocketInput(tmpfn, fileEventChan, filepath.Join(dir, "files"), &wg, 2)
	if err != nil {
		t.Fatal(err)
	}

	receiveDone := make(chan bool)

	go sendSocketMessage(t, message1, tmpfn)

	go func(myWg *sync.WaitGroup) {
		select {
		case <-fileEventChan:
			log.Fatal("expected no output from channel")
			myWg.Done()
		case <-time.After(5 * time.Second):
			// pass
		}
		close(receiveDone)
	}(&wg)

	si.Run()
	wg.Wait()
	<-receiveDone
}

func TestSocketInputNotStoredV2(t *testing.T) {
	dir, err := os.MkdirTemp("", "test")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	message1 := socketMessage{
		EventType: "fileinfo",
		FileInfo: socketMessageFileinfo{
			Filename: "/",
			FileID:   0,
			Stored:   false,
			Magic:    "PE32 executable (GUI) Intel 80386, for MS Windows",
			Sha256:   "40c38478248ab915fc6d988b54860d0eec3f1e6ff3c968d65ff8d0840614382f",
		},
	}
	fileEventChan := make(chan sampledb.FileInfoEvent)

	tmpfn := filepath.Join(dir, fmt.Sprintf("t%d", rand.Int63()))

	var wg sync.WaitGroup
	si, err := MakeSocketInput(tmpfn, fileEventChan, filepath.Join(dir, "files"), &wg, 2)
	if err != nil {
		t.Fatal(err)
	}

	receiveDone := make(chan bool)

	go sendSocketMessage(t, message1, tmpfn)

	go func(myWg *sync.WaitGroup) {
		select {
		case <-fileEventChan:
			log.Fatal("expected no output from channel")
			myWg.Done()
		case <-time.After(5 * time.Second):
			// pass
		}
		close(receiveDone)
	}(&wg)

	si.Run()
	wg.Wait()
	<-receiveDone

}
