// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package registry

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/DCSO/nightwatch/sampledb"

	"github.com/vimeo/go-magic/magic"
	"golang.org/x/crypto/sha3"
)

var magicFiles map[string]bool
var mutex sync.Mutex

func init() {
	magicFiles = make(map[string]bool)
}

// CalculateBasicHashes uses a multiWriter to efficiently calculate file hashes
// REF: http://marcio.io/2015/07/calculating-multiple-file-hashes-in-a-single-pass/
func CalculateBasicHashes(rd io.Reader) (sampledb.HashInfo, error) {
	var info sampledb.HashInfo

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()
	sha512Hash := sha512.New()
	sha3_512Hash := sha3.New512()

	// For optimum speed, Getpagesize returns the underlying system's memory page size.
	pageSize := os.Getpagesize()

	// wraps the Reader object into a new buffered reader to read the files in chunks
	// and buffering them for performance.
	reader := bufio.NewReaderSize(rd, pageSize)

	// creates a multiplexer Writer object that will duplicate all write
	// operations when copying data from source into all different hashing algorithms
	// at the same time
	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash, sha512Hash, sha3_512Hash)

	// Using a buffered reader, this will write to the writer multiplexer
	// so we only traverse through the file once, and can calculate all hashes
	// in a single byte buffered scan pass.
	//
	_, err := io.Copy(multiWriter, reader)
	if err != nil {
		return info, err
	}

	info.Md5 = hex.EncodeToString(md5Hash.Sum(nil))
	info.Sha1 = hex.EncodeToString(sha1Hash.Sum(nil))
	info.Sha256 = hex.EncodeToString(sha256Hash.Sum(nil))
	info.Sha512 = hex.EncodeToString(sha512Hash.Sum(nil))
	info.Sha3_512 = hex.EncodeToString(sha3_512Hash.Sum(nil))

	return info, nil
}

// MagicFromFile returns a magic string for the file in the given path.
func MagicFromFile(path string) string {
	cookie := magic.Open(magic.MAGIC_ERROR | magic.MAGIC_NONE)
	defer magic.Close(cookie)
	mutex.Lock()
	var mf []string
	for f := range magicFiles {
		mf = append(mf, f)
	}
	mutex.Unlock()
	ret := magic.Load(cookie, strings.Join(mf, ":"))
	if ret != 0 {
		return "unknown file type"
	}
	r := magic.File(cookie, path)
	return r
}
