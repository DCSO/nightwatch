// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package registry

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DCSO/nightwatch/sampledb"
	"github.com/DCSO/nightwatch/submitter"
	"github.com/DCSO/nightwatch/util"

	log "github.com/sirupsen/logrus"
)

type testPlugin struct {
	count map[string]int32
}

func (p *testPlugin) Name() string {
	return "test plugin"
}

func (p *testPlugin) ReInitialize() error {
	p.count = make(map[string]int32)
	return nil
}

func (p *testPlugin) ProcessFile(fs FileSample) (string, bool, error) {
	p.count[fs.OrigPath]++
	return "", false, nil
}

var p = &testPlugin{
	count: make(map[string]int32),
}

func init() {
	RegisterAnalysisPlugin(p)
}

func TestRescanTimeframe(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	s := submitter.MakeDummySubmitter()

	dbdir, err := os.MkdirTemp("", "dbdir")
	if err != nil {
		log.Fatal(err)
	}
	err = sampledb.InitDB(dbdir)
	if err != nil {
		log.Fatal(err)
	}
	defer sampledb.CloseDB()
	defer os.RemoveAll(dbdir)

	for n, d := range AnalysisPlugins {
		err = d.ReInitialize()
		if err != nil {
			log.Fatalf("Error initializing plugin [%v]: %v", n, err)
		}
	}

	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	util.CreateFilePair(1, []byte("foo bar"), 10, dir)
	err = PluginIterator(sampledb.FileInfoEvent{
		FilePath: filepath.Join(dir, "file.1"),
	}, s, nil)
	if err != nil {
		t.Fatal(err)
	}

	if p.count[filepath.Join(dir, "file.1")] != 1 {
		t.Fatal("file scan not counted")
	}

	// rescan within short time
	err = PluginIterator(sampledb.FileInfoEvent{
		FilePath: filepath.Join(dir, "file.1"),
	}, s, nil)
	if err != nil {
		t.Fatal(err)
	}

	if p.count[filepath.Join(dir, "file.1")] != 1 {
		t.Fatal("file scan counted")
	}

	oldRescanTimeframe := rescanTimeframe
	*rescanTimeframe = time.Second
	time.Sleep(2 * time.Second)

	// rescan after changing rescan timeframe
	err = PluginIterator(sampledb.FileInfoEvent{
		FilePath: filepath.Join(dir, "file.1"),
	}, s, nil)
	if err != nil {
		t.Fatal(err)
	}

	if p.count[filepath.Join(dir, "file.1")] != 2 {
		t.Fatal("file scan not counted")
	}

	rescanTimeframe = oldRescanTimeframe

	s.Finish()
}
