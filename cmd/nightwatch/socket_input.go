// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/DCSO/nightwatch/sampledb"
	"github.com/DCSO/nightwatch/util"

	log "github.com/sirupsen/logrus"
)

// SocketInput is an Input reading JSON EVE input from a Unix socket.
type SocketInput struct {
	EventChan     chan sampledb.FileInfoEvent
	Verbose       bool
	Running       bool
	StoreVersion  util.FilestoreVersion
	InputListener net.Listener
	StopChan      chan bool
	StoppedChan   chan bool
	WaitGroup     *sync.WaitGroup
	FileDir       string
	InputSocket   string
	Conn          net.Conn
}

type socketMessageFileinfo struct {
	Filename string `json:"filename"`
	FileID   uint64 `json:"file_id"`
	Stored   bool   `json:"stored"`
	Magic    string `json:"magic"`
	Sha256   string `json:"sha256"`
}

type socketMessage struct {
	EventType string                `json:"event_type"`
	FileInfo  socketMessageFileinfo `json:"fileinfo"`
}

func (si *SocketInput) handleServerConnection() {
	for {
		log.Debug("waiting for new connection")
		select {
		case <-si.StopChan:
			close(si.StoppedChan)
			return
		default:
			si.InputListener.(*net.UnixListener).SetDeadline(time.Now().Add(1e9))
			c, err := si.InputListener.Accept()
			if nil != err {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue
				}
				log.Info(err)
			}

			// we have a connection
			si.Conn = c
			reader := bufio.NewReader(c)

			for {
				if si.Conn == nil {
					break
				}

				line, err := reader.ReadBytes('\n')
				if err == io.EOF {
					break
				}

				var fullMsg interface{}
				var m socketMessage

				err = json.Unmarshal(line, &fullMsg)
				if err != nil {
					log.Errorf("could not unmarshal JSON '%s': %s", string(line), err)
					continue
				}
				err = json.Unmarshal(line, &m)
				if err != nil {
					log.Errorf("could not unmarshal JSON '%s': %s", string(line), err)
					continue
				}

				if m.EventType == "fileinfo" {
					log.Debugf("received fileinfo: %v", m)
					isAllowedFiletype := AllowedMagicPattern(m.FileInfo.Magic)

					switch ver := si.StoreVersion; ver {
					case util.V1:
						filePath := filepath.Join(si.FileDir, fmt.Sprintf("file.%v", m.FileInfo.FileID))
						if !isAllowedFiletype {
							log.Infof("file %s: filemagic '%s' did not match interesting pattern", filePath, m.FileInfo.Magic)
							err = DeleteFileSet(filePath, util.V1)
							if err != nil {
								log.Error(err)
								continue
							}
						} else {
							if m.FileInfo.Stored && m.FileInfo.FileID > 0 {
								si.WaitGroup.Add(1)
								fiev := sampledb.FileInfoEvent{
									StoreVersion: util.V1,
									JSONMessage:  fullMsg,
									FilePath:     filePath,
								}
								si.EventChan <- fiev
							} else {
								log.Debugf("ignoring file %d (filename: %s, stored: %v)",
									m.FileInfo.FileID, m.FileInfo.Filename, m.FileInfo.Stored)
							}
						}
					case util.V2:
						if m.FileInfo.Stored && len(m.FileInfo.Sha256) > 2 {
							fileBasePath := filepath.Join(si.FileDir, m.FileInfo.Sha256[:2], m.FileInfo.Sha256)
							if !isAllowedFiletype {
								log.Infof("file %s: filemagic '%s' did not match interesting pattern", fileBasePath, m.FileInfo.Magic)
								err = DeleteFileSet(fileBasePath, util.V2)
								if err != nil {
									log.Error(err)
									continue
								}
							} else {

								si.WaitGroup.Add(1)
								fiev := sampledb.FileInfoEvent{
									StoreVersion: util.V2,
									JSONMessage:  fullMsg,
									FilePath:     fileBasePath,
								}
								si.EventChan <- fiev
							}
						} else {
							log.Debugf("ignoring file %s (filename: '%s', stored: %v)",
								m.FileInfo.Sha256, m.FileInfo.Filename, m.FileInfo.Stored)
						}
					default:
					}
				}
			}
		}
	}
}

// MakeSocketInput returns a new SocketInput reading from the Unix socket
// inputSocket and writing parsed events to outChan. If no such socket could be
// created for listening, the error returned is set accordingly.
func MakeSocketInput(inputSocket string,
	outChan chan sampledb.FileInfoEvent, fileDir string, wg *sync.WaitGroup,
	version util.FilestoreVersion) (*SocketInput, error) {
	var err error

	si := &SocketInput{
		EventChan:    outChan,
		Verbose:      false,
		StopChan:     make(chan bool),
		WaitGroup:    wg,
		FileDir:      fileDir,
		StoreVersion: version,
		InputSocket:  inputSocket,
	}
	_, err = os.Stat(inputSocket)
	if err == nil {
		os.Remove(inputSocket)
	}
	si.InputListener, err = net.Listen("unix", inputSocket)
	if err != nil {
		return nil, err
	}
	return si, err
}

// Run starts the SocketInput
func (si *SocketInput) Run() {
	if !si.Running {
		si.Running = true
		si.StopChan = make(chan bool)
		go si.handleServerConnection()
	}
}

// Stop causes the SocketInput to stop reading from the socket and close all
// associated channels, including the passed notification channel.
func (si *SocketInput) Stop(stoppedChan chan bool) {
	if si != nil && si.Running {
		si.StoppedChan = stoppedChan
		if si.Conn != nil {
			si.Conn.Close()
			si.Conn = nil
		}
		close(si.StopChan)
		si.Running = false
		_, err := os.Stat(si.InputSocket)
		if err == nil {
			os.Remove(si.InputSocket)
		}
	} else {
		close(stoppedChan)
	}
}

// SetVerbose sets the input's verbosity level
func (si *SocketInput) SetVerbose(verbose bool) {
	si.Verbose = verbose
}
