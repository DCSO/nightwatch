// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package util

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/hillu/go-yara/v4"
	log "github.com/sirupsen/logrus"
)

// MakeYARARuleFile compiles a given YARA rule source and writes the compiled
// version to a given file name.
func MakeYARARuleFile(outfile string) error {
	// make sample YARA rules
	compiler, err := yara.NewCompiler()
	if err != nil {
		return err
	}
	defer compiler.Destroy()
	ruleFile, err := os.Open("../../testdata/simple.yara")
	if err != nil {
		return err
	}
	defer ruleFile.Close()
	err = compiler.AddFile(ruleFile, "test")
	if err != nil {
		return err
	}
	rules, err := compiler.GetRules()
	if err != nil {
		return err
	}
	defer rules.Destroy()
	err = rules.Save(outfile)
	return err
}

// Min returns the smaller of the passed int values.
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CreateFilePairV2 creates a file with given contents in a given directory,
// matching the naming scheme of filestore v2.
func CreateFilePairV2(number int, contents []byte, blockSize int, dir string) {
	time.Sleep(time.Duration(rand.Intn(200)) * time.Millisecond)
	contentBytes := []byte(contents)
	sum := sha256.Sum256(contentBytes)
	hashString := fmt.Sprintf("%x", sum)

	subPath := filepath.Join(dir, hashString[:2])
	err := os.MkdirAll(subPath, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	filename := filepath.Join(subPath, hashString)

	log.Printf("creating file %s", filename)
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	f.Write(contentBytes[0:Min(len(contents), blockSize)])
	f.Close()
	written := blockSize
	// we emulate Suricata's behaviour of writing files by appending chunks
	for written < len(contents) {
		log.Debug("writing", filename, "position", written, "to", written+blockSize)
		f, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		f.Write(contentBytes[written : written+blockSize])
		f.Close()
		written += blockSize
	}
	filename = fmt.Sprintf("%s.1.json", filename)
	f, err = os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	testJSON := map[string]string{
		"foo":      "bar",
		"filename": filename,
	}
	out, err := json.Marshal(testJSON)
	if err != nil {
		log.Fatal(err)
	}
	f.Write(out)
	f.Close()
}

// CreateFilePair creates a file with given contents in a given directory, named
// "file.<number>" as well as a meta file "file.<number>.meta", emulating
// Suricata's file extraction behaviour. A random delay of up to 200ms is used
// before writing to slow down file creation a bit. Files are written in chunks,
// opening and closing the file for each individual chunk just as Suricata does.
func CreateFilePair(number int, contents []byte, blockSize int, dir string) {
	time.Sleep(time.Duration(rand.Intn(200)) * time.Millisecond)
	filename := filepath.Join(dir, fmt.Sprintf("file.%d", number))
	contentBytes := append([]byte(contents), make([]byte, blockSize)...)
	log.Printf("creating file %s", filename)
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	f.Write(contentBytes[0:Min(len(contents), blockSize)])
	f.Close()
	written := blockSize
	// we emulate Suricata's behaviour of writing files by appending chunks
	for written < len(contents) {
		log.Debug("writing", filename, "position", written, "to", written+blockSize)
		f, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		f.Write(contentBytes[written : written+blockSize])
		f.Close()
		written += blockSize
	}
	filename = filepath.Join(dir, fmt.Sprintf("file.%d.meta", number))
	f, err = os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	f.Write([]byte("foo"))
	f.Close()
}

// CreateFilePairMoved creates a file with given contents in a given directory,
// named "file.<number>" as well as a metafile "file.<number>.meta". However,
// unlike CreateFilePair, CreateFilePairMoved creates the files outside the
// target directory and moves it in later, simulating 'atomic' file creation.
func CreateFilePairMoved(number int, contents []byte, dir string) {
	tmpdir, err := os.MkdirTemp("", "tmp")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	CreateFilePair(number, contents, len(contents), tmpdir)
	os.Rename(filepath.Join(tmpdir, fmt.Sprintf("file.%d", number)),
		filepath.Join(dir, fmt.Sprintf("file.%d", number)))
	os.Rename(filepath.Join(tmpdir, fmt.Sprintf("file.%d.meta", number)),
		filepath.Join(dir, fmt.Sprintf("file.%d.meta", number)))
}

// CreateFilePairWithTime creates a file pair like CreateFilePair, but also sets
// atime and mtime of the resulting file to the given value.
func CreateFilePairWithTime(number int, contents []byte, blockSize int,
	dir string, mtime time.Time) {
	CreateFilePair(number, contents, blockSize, dir)
	// we treat mtime as atime as well
	os.Chtimes(filepath.Join(dir, fmt.Sprintf("file.%d", number)), mtime, mtime)
}
