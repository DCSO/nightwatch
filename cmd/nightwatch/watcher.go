// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/DCSO/nightwatch/registry"
	"github.com/DCSO/nightwatch/sampledb"
	"github.com/DCSO/nightwatch/submitter"
	"github.com/DCSO/nightwatch/uploader"
	"github.com/DCSO/nightwatch/util"

	log "github.com/sirupsen/logrus"
)

var (
	metafileReg      = regexp.MustCompile(`\.(json|meta)$`)
	droppedFileReg   = regexp.MustCompile(`(file\.[0-9]+|[0-9a-fA-F]{2}.[0-9a-fA-F]{64})$`)
	droppedFileV1Reg = regexp.MustCompile(`file\.[0-9]+$`)
	droppedFileV2Reg = regexp.MustCompile(`[0-9a-fA-F]{2}.[0-9a-fA-F]{64}$`)
)

const (
	numWorkers = 5
)

func intToStoreVersion(v int) (util.FilestoreVersion, error) {
	if v < 1 || v > 2 {
		return 0, fmt.Errorf("invalid filestore version: %d", v)
	}
	switch v {
	case 1:
		return util.V1, nil
	case 2:
		return util.V2, nil
	}
	return 0, fmt.Errorf("invalid filestore version")
}

// Watcher represents a watching context on a given directory, allowing the
// process to be started and stopped concurrently as a component.
type Watcher struct {
	StartStopLock     sync.Mutex
	StopperChan       chan bool
	FinishNotifyChan  chan bool
	ScanCandidateChan chan sampledb.FileInfoEvent
	IsRunning         bool
	FileDir           string
	FilestoreVersion  util.FilestoreVersion
	WaitGroup         sync.WaitGroup
	SocketInput       *SocketInput
	Uploader          *uploader.Uploader
}

// backlogBuilder is called on program start to make a quick check of the files
// directory to make sure we don't miss a file.
func (w *Watcher) backlogBuilder(path string, submitter submitter.Submitter, storeVersion int) {
	files := make([]string, 0)
	log.Infof("building backlog")
	sv, _ := intToStoreVersion(storeVersion)
	err := filepath.Walk(path,
		func(fpath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			fi, err := os.Stat(fpath)
			if err != nil {
				return err
			}
			switch mode := fi.Mode(); {
			case mode.IsRegular():
				// we only want to look at regular non-metafiles
				if droppedFileReg.Match([]byte(fpath)) {
					magic := registry.MagicFromFile(fpath)
					if !AllowedMagicPattern(magic) {
						err = DeleteFileSet(fpath, sv)
						if err != nil {
							log.Error(err)
							return nil
						}
					} else {
						files = append(files, fpath)
					}
				}
			default:
				// pass
			}
			return nil
		})
	if err != nil {
		log.Println(err)
	}
	for _, f := range files {
		jsonFiles, err := filepath.Glob(fmt.Sprintf("%s.*.json", f))
		if err != nil {
			log.Error(err)
			continue
		}
		for _, jf := range jsonFiles {
			data, err := os.ReadFile(jf)
			if err != nil {
				log.Error(err)
				continue
			}
			var jm interface{}
			err = json.Unmarshal(data, &jm)
			if err != nil {
				log.Error(err)
				continue
			}
			log.Debugf("found %s, submitting...", jf)
			w.WaitGroup.Add(1)
			w.ScanCandidateChan <- sampledb.FileInfoEvent{
				JSONMessage: jm,
				FilePath:    f,
			}
		}
		metaFiles, err := filepath.Glob(fmt.Sprintf("%s.meta", f))
		if err != nil {
			log.Error(err)
			continue
		}
		for _, mf := range metaFiles {
			data, err := os.ReadFile(mf)
			if err != nil {
				log.Error(err)
				continue
			}
			log.Debugf("found %s, submitting...", mf)
			w.WaitGroup.Add(1)
			w.ScanCandidateChan <- sampledb.FileInfoEvent{
				MetafileText: string(data),
				FilePath:     f,
			}
		}
	}
	w.WaitGroup.Wait()
	log.Infof("finished building backlog")
}

// fileWorker takes a file path and calls the PluginIterator to let the plugins
// do their analysis jobs.
func (w *Watcher) fileWorker(submitter submitter.Submitter) {
	for fiev := range w.ScanCandidateChan {
		log.Debugf("worker grabbed file %s for processing", fiev.FilePath)
		err := registry.PluginIterator(fiev, submitter, w.Uploader)
		if err != nil {
			log.Error("PluginIterator: ", err)
		}
		w.WaitGroup.Done()
	}
	log.Info("worker terminated")
}

// MakeWatcher returns a new, stopped Watcher. Will emit a value on finishNotify
// channel when finished.
func MakeWatcher(finishNotify chan bool, submitter submitter.Submitter,
	uploader *uploader.Uploader) *Watcher {
	w := &Watcher{
		IsRunning:         false,
		FinishNotifyChan:  finishNotify,
		ScanCandidateChan: make(chan sampledb.FileInfoEvent, 10000),
		Uploader:          uploader,
	}
	for i := 0; i < numWorkers; i++ {
		go w.fileWorker(submitter)
	}
	return w
}

// Run starts the watcher on the given socketPath, with files being located in the
// given directory.
func (w *Watcher) Run(directory string, storeVersion int, socketPath string) error {
	var err error

	if w.IsRunning {
		return fmt.Errorf("watcher already running")
	}

	w.StartStopLock.Lock()

	w.FileDir = directory
	w.IsRunning = true
	w.FilestoreVersion, err = intToStoreVersion(storeVersion)
	if err != nil {
		log.Info(err)
		return err
	}

	w.SocketInput, err = MakeSocketInput(socketPath, w.ScanCandidateChan,
		w.FileDir, &w.WaitGroup, w.FilestoreVersion)
	if err != nil {
		w.StartStopLock.Unlock()
		return err
	}

	log.Infof("Watcher running on socket %s, filestore %s, filestore version %d", socketPath, directory, storeVersion)

	w.SocketInput.Run()

	w.StartStopLock.Unlock()

	return nil
}

// Stop causes the watcher to cease reacting to events on the target directory.
func (w *Watcher) Stop() {
	w.StartStopLock.Lock()
	w.SocketInput.Stop(w.FinishNotifyChan)
	w.IsRunning = false
	w.FileDir = "<none>"
	w.StartStopLock.Unlock()
}

// Finish cleans up side effects of a Watcher instance.
func (w *Watcher) Finish() {
	close(w.ScanCandidateChan)
}
