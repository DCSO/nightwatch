// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	// MaxAge is the maximal age of a file before it is flagged for deletion.
	MaxAge = flag.Duration("maxage", 365*24*time.Hour, "max age of file before being cleaned up")
	// MaxSpace is the space limit (in MB) of all files in the tracked directory.
	// Old file pairs will be deleted once this limit is exceeded.
	MaxSpace = flag.Uint("maxspace", 20000, "max total space used for files in MB")
)

// Janitor represents a concurrent helper object that periodically checks a
// directory, deleting either files older than a given age or the files older
// than the oldest file such that the set of the files newer than that file does
// not exceed a given space limit, whatever is more specific.
type Janitor struct {
	StopperChan      chan bool
	IsRunning        bool
	FinishNotifyChan chan bool
	WatchDir         string
	StartStopLock    sync.Mutex
	CheckTick        time.Duration
}

// MakeJanitor creates a new Janitor and emits a value on the given channel
// when it has been stopped.
func MakeJanitor(finishNotify chan bool) *Janitor {
	return &Janitor{
		IsRunning:        false,
		FinishNotifyChan: finishNotify,
		CheckTick:        60 * time.Second,
	}
}

type removableFile struct {
	Age  time.Duration
	Path string
	Size int64
}

type byAge []removableFile

func (a byAge) Len() int {
	return len(a)
}

func (a byAge) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a byAge) Less(i, j int) bool {
	return a[i].Age < a[j].Age
}

// Run starts a Janitor on the given directory.
func (w *Janitor) Run(directory string) error {
	if w.IsRunning {
		return fmt.Errorf("janitor already running on directory %s", w.WatchDir)
	}

	w.StartStopLock.Lock()

	w.StopperChan = make(chan bool)
	w.WatchDir = directory
	w.IsRunning = true

	go func() {
		for {
			select {
			case <-time.After(w.CheckTick):
				// expire old files
				filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						log.Warn(err)
						return nil
					}
					if metafileReg.Match([]byte(path)) {
						return nil
					}
					timeSince := time.Since(info.ModTime())
					if timeSince > *MaxAge {
						myerr := os.Remove(path)
						if myerr != nil {
							log.Warn(myerr)
						}
						myerr = os.Remove(fmt.Sprintf("%s.meta", path))
						if myerr != nil {
							log.Debug(myerr)
						}
						metajsonfiles, myerr := filepath.Glob(fmt.Sprintf("%s.*.json", path))
						if myerr != nil {
							log.Debug(myerr)
						}
						for _, f := range metajsonfiles {
							delerr := os.Remove(f)
							if myerr != nil {
								log.Debug(delerr)
							}
						}
						log.Infof("%s: older than threshold (%v), cleaned", info.Name(), timeSince)
					}
					return nil
				})
				// sort remaining files by age and determine space break
				var files []removableFile
				filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						log.Warn(err)
						return nil
					}
					if info.IsDir() {
						return nil
					}
					if metafileReg.Match([]byte(path)) {
						return nil
					}
					files = append(files, removableFile{
						Age:  time.Since(info.ModTime()),
						Path: path,
						Size: info.Size(),
					})
					return nil
				})
				sort.Sort(byAge(files))
				// delete oldest files exceeding space limit
				var sum uint
				for _, item := range files {
					sum += uint(item.Size)
					if sum > *MaxSpace*1024*1024 {
						myerr := os.Remove(item.Path)
						if myerr != nil {
							log.Warn(myerr)
						}
						myerr = os.Remove(fmt.Sprintf("%s.meta", item.Path))
						if myerr != nil {
							log.Debug(myerr)
						}
						metajsonfiles, myerr := filepath.Glob(fmt.Sprintf("%s.*.json", item.Path))
						if myerr != nil {
							log.Debug(myerr)
						}
						for _, f := range metajsonfiles {
							delerr := os.Remove(f)
							if myerr != nil {
								log.Debug(delerr)
							}
						}
						log.Infof("%s: cleaned to reclaim space (%d bytes)", item.Path, item.Size)
					}
				}
			case <-w.StopperChan:
				close(w.FinishNotifyChan)
				return
			}
		}
	}()
	w.StartStopLock.Unlock()

	return nil
}

// Stop causes the janitor to stop limiting the contents of the target
// directory.
func (w *Janitor) Stop() {
	w.StartStopLock.Lock()
	w.IsRunning = false
	w.WatchDir = "<none>"
	close(w.StopperChan)
	w.StartStopLock.Unlock()
}
