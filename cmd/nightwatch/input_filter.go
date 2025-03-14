// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/DCSO/nightwatch/util"

	log "github.com/sirupsen/logrus"
)

var (
	allowedMagicPatterns = make(map[string]*regexp.Regexp)
)

func init() {
	allowedMagicPatterns["WinExecutables"] = regexp.MustCompile("(for MS Windows|(ELF|Mach-O).*(executable|shared object))")
}

// AllowedMagicPattern checks whether a magic string is within the definition
// of files that are relevant for nightwatch, as given via a set of regular
// expressions on magic strings.
func AllowedMagicPattern(magic string) bool {
	for _, pattern := range allowedMagicPatterns {
		if pattern.Match([]byte(magic)) {
			return true
		}
	}
	return false
}

// DeleteFileSet deletes both an extracted file and its metafile.
func DeleteFileSet(filePath string, version util.FilestoreVersion) error {
	var err error
	var filePat *regexp.Regexp
	log.Infof("removing file: %s", filePath)
	switch version {
	case util.V1:
		filePat = droppedFileV1Reg
	case util.V2:
		filePat = droppedFileV2Reg
	}
	if !filePat.Match([]byte(filePath)) {
		log.Warnf("was going to delete file %s, skipped as it does not look like an extracted file", filePath)
		return nil
	}
	_, err = os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debugf("missing file to delete: %s", filePath)
		} else {
			log.Warnf("error checking file to delete %s: %s", filePath, err.Error())
		}
	} else {
		os.Remove(filePath)
	}
	switch version {
	case util.V1:
		metaFile := filepath.Join(fmt.Sprintf("%s.meta", filePath))
		log.Debugf("removing metafile: %s", metaFile)
		_, err = os.Stat(metaFile)
		if err != nil {
			if os.IsNotExist(err) {
				log.Debugf("missing metafile: %s", metaFile)
			} else {
				log.Warnf("error checking metafile %s: %s", metaFile, err.Error())
			}
		} else {
			os.Remove(metaFile)
		}
	case util.V2:
		metaFiles, err := filepath.Glob(fmt.Sprintf("%s.*.json", filePath))
		if err == nil {
			for _, metaFile := range metaFiles {
				log.Debugf("removing metafile: %s", metaFile)
				_, err = os.Stat(metaFile)
				if err != nil {
					if os.IsNotExist(err) {
						log.Debugf("missing metafile: %s", metaFile)
					} else {
						log.Warnf("error checking metafile %s: %s", metaFile, err.Error())
					}
				} else {
					os.Remove(metaFile)
				}
			}
		} else {
			log.Warnf("could not glob metafiles for file %s", filePath)
		}
	}
	return nil
}
