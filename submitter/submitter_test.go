// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package submitter

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqptest"
	"github.com/NeowayLabs/wabbit/amqptest/server"
	log "github.com/sirupsen/logrus"
)

func TestInvalidReconnector(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	submitter, err := MakeAMQPSubmitterWithReconnector("localhost:9991/%2f", "sensor",
		"sensor", "nightwatch", true, func(url string) (wabbit.Conn, string, error) {
			return nil, "", fmt.Errorf("error")
		})
	if submitter != nil || err == nil {
		t.Fail()
	}
}

func TestSubmitter(t *testing.T) {
	serverURL := "amqp://sensor:sensor@localhost:9998/%2f/"
	log.SetLevel(log.DebugLevel)

	// start mock server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()

	// set up consumer
	var buf bytes.Buffer
	allDone := make(chan bool)
	c, err := NewConsumer(serverURL, "nightwatch", "direct", "nightwatch",
		"nightwatch", "nightwatch-test1", func(d wabbit.Delivery) {
			buf.Write(d.Body())
			if buf.Len() == 4 {
				allDone <- true
			}
		})
	if err != nil {
		t.Fatal(err)
	}

	// set up submitter
	submitter, err := MakeAMQPSubmitterWithReconnector("localhost:9998/%2f", "sensor",
		"sensor", "nightwatch", true, func(url string) (wabbit.Conn, string, error) {
			// we pass in a custom reconnector which uses the amqptest implementation
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, "direct", err
		})
	if err != nil {
		t.Fatal(err)
	}

	// send some messages...
	submitter.Submit([]byte("1"))
	submitter.Submit([]byte("2"))
	submitter.Submit([]byte("3"))
	submitter.Submit([]byte("4"))

	// ... and wait until they are received and processed
	<-allDone
	// check if order and length is correct
	if buf.String() != "1234" {
		t.Fail()
	}

	// tear down test setup
	submitter.Finish()
	fakeServer.Stop()
	c.Shutdown()

}

func TestSubmitterReconnect(t *testing.T) {
	serverURL := "amqp://sensor:sensor@localhost:9992/%2f/"
	log.SetLevel(log.DebugLevel)

	// start mock server
	fakeServer := server.NewServer(serverURL)
	fakeServer.Start()

	// set up consumer
	var buf bytes.Buffer
	var bufLock sync.Mutex
	done := make(chan bool)
	c, err := NewConsumer(serverURL, "nightwatch", "direct", "nightwatch2",
		"nightwatch", "nightwatch-test2", func(d wabbit.Delivery) {
			bufLock.Lock()
			buf.Write(d.Body())
			log.Printf("received '%s', buf length %d", d.Body(), buf.Len())
			if buf.Len() == 2 {
				done <- true
			}
			bufLock.Unlock()
		})
	if err != nil {
		t.Fatal(err)
	}

	// set up submitter
	submitter, err := MakeAMQPSubmitterWithReconnector("localhost:9992/%2f", "sensor",
		"sensor", "nightwatch", true, func(url string) (wabbit.Conn, string, error) {
			// we pass in a custom reconnector which uses the amqptest implementation
			var conn wabbit.Conn
			conn, err = amqptest.Dial(url)
			return conn, "direct", err
		})
	if err != nil {
		t.Fatal(err)
	}
	defer submitter.Finish()

	// send some messages...
	submitter.Submit([]byte("A"))
	submitter.Submit([]byte("B"))
	stopped := make(chan bool)
	restarted := make(chan bool)
	<-done
	go func() {
		fakeServer.Stop()
		close(stopped)
		time.Sleep(5 * time.Second)
		fakeServer := server.NewServer(serverURL)
		fakeServer.Start()
		close(restarted)
	}()
	<-stopped
	log.Info("server stopped")

	// these are buffered on client side because submitter will not publish
	// with immediate flag set
	submitter.Submit([]byte("C"))
	submitter.Submit([]byte("D"))

	<-restarted
	log.Info("server restarted")

	// reconnect consumer
	c.Shutdown()
	c2, err := NewConsumer(serverURL, "nightwatch", "direct", "nightwatch2",
		"nightwatch", "nightwatch-test2", func(d wabbit.Delivery) {
			bufLock.Lock()
			buf.Write(d.Body())
			log.Printf("received '%s', buf length %d", d.Body(), buf.Len())
			if buf.Len() == 6 {
				done <- true
			}
			bufLock.Unlock()
		})
	if err != nil {
		t.Fatal(err)
	}

	submitter.Submit([]byte("E"))
	submitter.Submit([]byte("F"))

	// ... and wait until they are received and processed

	<-done
	log.Debug("All done")

	// check if order and length is correct
	bufLock.Lock()
	log.Info(buf.String())
	if buf.String() != "ABCDEF" {
		t.Fail()
	}
	bufLock.Unlock()

	// tear down test setup
	c2.Shutdown()
	fakeServer.Stop()
}
