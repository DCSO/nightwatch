// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package sampledb

import (
	"encoding/json"
	"errors"
	"path/filepath"

	bolt "github.com/etcd-io/bbolt"
	log "github.com/sirupsen/logrus"
)

const (
	bucketName = "SAMPLES"

	// DatabaseName is the file name of the database file.
	DatabaseName = "files.db"
)

var filesDB *bolt.DB

// InitDB is used to initialize the bolt database on startup.
func InitDB(dataPath string) error {
	var err error
	// Try to open the database file. If not present it will be created.
	filesDB, err = bolt.Open(filepath.Join(dataPath, DatabaseName), 0600, nil)
	if err != nil {
		return err
	}
	log.Debug("Database initialized:", filesDB.Path())
	return nil
}

// CloseDB should be called before the program terminates.
func CloseDB() error {
	return filesDB.Close()
}

// CreateSampleEntry creates a database entry for a newly observed file.
func CreateSampleEntry(fv FileVerdict) error {
	encoded, err := json.Marshal(fv)
	if err != nil {
		return err
	}

	err = filesDB.Update(func(tx *bolt.Tx) error {
		var bucket *bolt.Bucket
		bucket, err = tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(fv.Hashes.Sha512), encoded)
		return err
	})
	if err == nil {
		log.Debug("Stored sample entry in database:", fv.Hashes.Sha512)
	}
	return err
}

// GetSampleEntry queries the database for a given sha512 hash to see if there
// is already a FileVerdict report for it.
func GetSampleEntry(hash string) (FileVerdict, error) {
	var data []byte
	fv := FileVerdict{}

	err := filesDB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return errors.New("missing bucket")
		}
		data = bucket.Get([]byte(hash))
		return nil
	})
	if err != nil || len(data) == 0 {
		return fv, err
	}

	err = json.Unmarshal(data, &fv)
	return fv, err
}
