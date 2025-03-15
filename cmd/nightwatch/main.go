// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package main

import (
	"flag"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"sync"
	"syscall"

	"github.com/DCSO/nightwatch/registry"
	"github.com/DCSO/nightwatch/sampledb"
	"github.com/DCSO/nightwatch/submitter"
	"github.com/DCSO/nightwatch/uploader"

	// Plugins are registered using the following imports
	_ "github.com/DCSO/nightwatch/plugins/yarascanner"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqp"
	"github.com/NeowayLabs/wabbit/amqptest"
	log "github.com/sirupsen/logrus"
)

var (
	// testMode is used to invoke some automatic testing behaviour in main()
	testMode bool
	testDir  string

	// stopChan is used to notify the reader of a completed main()
	stopChan chan bool

	// SigChan is a channel receiving os.Signal instances to control runtime behaviour
	sigChan       = make(chan os.Signal, 1)
	sigChanClosed = make(chan bool)

	// initLock is a mutex protecting the critical section of plugin reloading
	initLock sync.Mutex
)

func testWrapper(testdir string, stopNotify chan bool) {
	testMode = true
	testDir = testdir
	stopChan = make(chan bool)
	go main()
	<-stopChan
	testMode = false
	close(stopNotify)
}

// InitializePlugins calls the plugins' Initialize functions to give them a
// chance to prepare their matching engines.
func InitializePlugins() {
	initLock.Lock()
	for n, d := range registry.AnalysisPlugins {
		err := d.ReInitialize()
		if err != nil {
			log.Fatalf("Error initializing plugin [%v]: %v", n, err)
		}
	}
	log.Infof("[%v] plugins successfully initialized", len(registry.AnalysisPlugins))
	initLock.Unlock()
}

func main() {
	var err error
	var s submitter.Submitter
	var u *uploader.Uploader
	var filestoreVersion = flag.Int("storeversion", 2, "Filestore version")
	var sockPath = flag.String("socket", "/tmp/files.sock", "Path for fileinfo EVE input socket")
	var suriFilesDir = flag.String("dir", "/var/log/suricata/filestore", "Directory where suricata stores files")
	var logPath = flag.String("log", "/var/log/", "Path for nightwatch log files")
	var dataPath = flag.String("data", "/var/lib/nightwatch/", "Path for the file database")
	var amqpURI = flag.String("amqpuri", "localhost:5672", "Endpoint and port for the AMQP connection")
	var amqpExchange = flag.String("amqpexch", "nightwatch", "Exchange to post messages to")
	var amqpUser = flag.String("amqpuser", "sensor", "User name for the AMQP connection")
	var amqpPass = flag.String("amqppass", "sensor", "Password for the AMQP connection")
	var dummy = flag.Bool("dummy", false, "Log verdicts to file instead of submitting to AMQP")
	var profileFile = flag.String("proffile", "", "Dump profiling information to file")
	var memProfileFile = flag.String("mproffile", "", "Dump memory profiling information to file")
	var uploadEndpoint = flag.String("uploadendpoint", "", "Endpoint for suspicious file S3 upload")
	var uploadAccessKey = flag.String("uploadaccesskey", "", "Access key for S3 upload")
	var uploadSecretAccessKey = flag.String("uploadsecretaccesskey", "", "Secret access key for S3 upload")
	var uploadBucketName = flag.String("uploadbucket", "", "Bucket name for S3 upload")
	var uploadRegion = flag.String("uploadregion", "", "Region for S3 upload")
	var uploadScratchDir = flag.String("uploadscratchdir", "/tmp/nightwatch_scratch", "Temp directory for S3 upload")
	var uploadSSL = flag.Bool("uploadssl", false, "Use SSL for S3 upload")
	var profSrv = flag.Bool("profsrv", false, "Enable profiling server on port 6060")
	var verbose = flag.Bool("verbose", false, "Verbose output")
	var logJSON = flag.Bool("logjson", false, "JSON log output")
	flag.Parse()

	// Use temporary test directories
	if testMode {
		*logPath = testDir
		*dataPath = filepath.Join(testDir, "db")
		*suriFilesDir = filepath.Join(testDir, "files")
		*amqpExchange = "nightwatch"
		*amqpURI = "localhost:9999/%2f"
		*sockPath = filepath.Join(testDir, "files.sock")
	}

	// Configure logging to file
	if len(*logPath) > 0 || testMode {
		if _, err = os.Stat(*logPath); os.IsNotExist(err) {
			log.Infof("Log directory %s does not exist, trying to create it", *logPath)
			err = os.MkdirAll(*logPath, os.ModePerm)
			if err != nil {
				log.Fatal(err)
			}
		}
		f, myerr := os.OpenFile(filepath.Join(*logPath, "nightwatch.log"),
			os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if myerr != nil {
			log.Fatal(myerr)
		}
		defer func() {
			f.Close()
			log.SetOutput(os.Stdout)
		}()
		log.SetOutput(f)
	}

	if *logJSON {
		log.SetFormatter(&log.JSONFormatter{})
	}

	if *verbose {
		log.Info("verbose log output enabled")
		log.SetLevel(log.DebugLevel)
	}

	// Optional profiling
	if *profileFile != "" {
		var f io.Writer
		f, err = os.Create(*profileFile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *profSrv && !testMode {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	// Create submitter
	if *dummy {
		log.Info("disabling verdict submission")
		s = submitter.MakeDummySubmitter()
	} else {
		s, err = submitter.MakeAMQPSubmitterWithReconnector(*amqpURI, *amqpUser, *amqpPass,
			*amqpExchange, *verbose, func(url string) (wabbit.Conn, string, error) {
				log.Info(url)
				if testMode {
					c, e := amqptest.Dial(url)
					return c, "direct", e
				}
				c, e := amqp.Dial(url)
				return c, "fanout", e
			})
		if err != nil {
			log.Fatal(err)
		}
	}
	defer s.Finish()

	// Create uploader
	if len(*uploadEndpoint) > 0 {
		err = os.MkdirAll(*uploadScratchDir, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
		u, err = uploader.MakeS3Uploader(uploader.S3Credentials{
			Endpoint:        *uploadEndpoint,
			AccessKey:       *uploadAccessKey,
			SecretAccessKey: *uploadSecretAccessKey,
			BucketName:      *uploadBucketName,
			Region:          *uploadRegion,
		}, *uploadSSL, *suriFilesDir, *uploadScratchDir, s)
		if err != nil {
			log.Fatal(err)
		}
	}

	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for sig := range sigChan {
			log.Infof("received signal %v, no handler set up yet", sig)
		}
		close(sigChanClosed)
	}()

	// Setup database connection and create the database file if not exist
	if _, err = os.Stat(*dataPath); os.IsNotExist(err) {
		log.Infof("Database directory %s does not exist, trying to create it", *dataPath)
		os.MkdirAll(*dataPath, os.ModePerm)
	}
	err = sampledb.InitDB(*dataPath)
	if err != nil {
		log.Fatal(err)
	}
	defer sampledb.CloseDB()

	InitializePlugins()

	// Prepare watcher
	finishNotify := make(chan bool)
	w := MakeWatcher(finishNotify, s, u)
	w.backlogBuilder(*suriFilesDir, s, *filestoreVersion)

	janitorNotify := make(chan bool)
	j := MakeJanitor(janitorNotify)

	// Clear previous stub handler
	signal.Reset()
	close(sigChan)
	<-sigChanClosed
	sigChan = make(chan os.Signal, 1)

	// Register live handlers
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP,
		syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
	SigLoop:
		for {
			sig := <-sigChan
			switch sig {
			case syscall.SIGHUP:
				// reload YARA rules
				log.Info("Received SIGHUP, reinitializing plugins")
				InitializePlugins()
			case syscall.SIGUSR1:
				log.Info("Received SIGUSR1, rescanning", *suriFilesDir)
				w.backlogBuilder(*suriFilesDir, s, *filestoreVersion)
			case syscall.SIGUSR2:
				log.Info("Received SIGUSR2, rescanning from scratch", *suriFilesDir)
				sampledb.CloseDB()
				err = os.Remove(filepath.Join(*dataPath, sampledb.DatabaseName))
				if err != nil {
					log.Fatal(err)
				}
				err = sampledb.InitDB(*dataPath)
				if err != nil {
					log.Fatal(err)
				}
				w.backlogBuilder(*suriFilesDir, s, *filestoreVersion)
			case os.Interrupt, syscall.SIGTERM:
				log.Info("Received request to stop, stopping janitor and watcher...")
				if len(*uploadEndpoint) > 0 {
					u.Stop()
				}
				w.Finish()
				w.Stop()
				j.Stop()
				break SigLoop
			}
		}
	}()

	// start watching directory events...
	err = w.Run(*suriFilesDir, *filestoreVersion, *sockPath)
	if err != nil {
		log.Fatal(err)
	}
	j.Run(*suriFilesDir)

	// ...until the watcher is stopped
	<-finishNotify
	<-janitorNotify

	log.Info("stopped janitor and watcher")

	if testMode {
		close(stopChan)
	}

	if *memProfileFile != "" {
		f, err := os.Create(*memProfileFile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
		f.Close()
	}
}
