// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package sampledb

import (
	"time"

	"github.com/DCSO/nightwatch/util"
)

// FileVerdict is returned by the AnalysisPlugins
type FileVerdict struct {
	Suspicious     bool
	SuspiciousVia  []string `json:"SuspiciousVia,omitempty"`
	Reported       bool
	Reasons        map[string]interface{}
	SensorID       string
	Time           time.Time
	CollectionTime time.Time
	Filename       string
	Size           int64
	MetaFile       []byte `json:"MetaFile,omitempty"`
	Hashes         HashInfo
	Metadata       interface{} `json:"Metadata,omitempty"`
	Magic          string
	Uploaded       bool
	UploadLocation string `json:"UploadLocation,omitempty"`
}

// HashInfo contains file hash information for the verdict struct
type HashInfo struct {
	Md5      string
	Sha1     string
	Sha256   string
	Sha512   string
	Sha3_512 string
}

// FileInfoEvent is a struct containing both the file path as well
// as the original
type FileInfoEvent struct {
	StoreVersion util.FilestoreVersion
	JSONMessage  interface{}
	MetafileText string
	FilePath     string
}
