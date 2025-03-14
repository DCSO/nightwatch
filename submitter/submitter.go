// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package submitter

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/NeowayLabs/wabbit"
	origamqp "github.com/rabbitmq/amqp091-go"
	log "github.com/sirupsen/logrus"
)

// SensorID is a unique string identifier for the submitting host.
var SensorID string

func init() {
	var err error
	SensorID, err = getSensorID()
	if err != nil {
		log.Fatal(err)
	}
}

func getSensorID() (string, error) {
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		return os.Hostname()
	}
	b, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return os.Hostname()
	}
	return strings.TrimSpace(string(b)), nil
}

const amqpReconnDelay = 2 * time.Second

// Submitter is an interface for an entity that sends JSON data to an endpoint
type Submitter interface {
	Submit(jsonData []byte) error
	Finish()
}

// AMQPSubmitter sends verdicts to a RabbitMQ exchange.
type AMQPSubmitter struct {
	URL              string
	User             string
	Pass             string
	Exchange         string
	Verbose          bool
	Conn             wabbit.Conn
	Channel          wabbit.Channel
	StopReconnection chan bool
	ChanMutex        sync.Mutex
	ConnMutex        sync.Mutex
	ErrorChan        chan wabbit.Error
	Reconnector      func(string) (wabbit.Conn, string, error)
}

func reconnectOnFailure(s *AMQPSubmitter) {
	for {
		select {
		case <-s.StopReconnection:
			return
		case rabbitErr := <-s.ErrorChan:
			if rabbitErr != nil {
				log.Warnf("RabbitMQ connection failed: %s", rabbitErr.Reason())
				for {
					time.Sleep(amqpReconnDelay)
					connErr := s.connect()
					if connErr != nil {
						log.Warnf("RabbitMQ error: %s", connErr)
					} else {
						log.Infof("Reestablished connection to %s", s.URL)
						s.ConnMutex.Lock()
						s.Conn.NotifyClose(s.ErrorChan)
						s.ConnMutex.Lock()
						break
					}
				}
			}
		}
	}
}

func (s *AMQPSubmitter) connect() error {
	var err error
	var exchangeType string

	s.ConnMutex.Lock()
	s.Conn, exchangeType, err = s.Reconnector(s.URL)
	s.ConnMutex.Unlock()
	if err != nil {
		return err
	}
	s.ChanMutex.Lock()
	s.Channel, err = s.Conn.Channel()
	s.ChanMutex.Unlock()
	if err != nil {
		s.ConnMutex.Lock()
		s.Conn.Close()
		s.ConnMutex.Unlock()
		return err
	}
	// We do not want to declare an exchange on non-default connection methods,
	// as they may not support all exchange types. For instance amqptest does
	// not support 'fanout'.
	err = s.Channel.ExchangeDeclare(
		s.Exchange,   // name
		exchangeType, // type
		wabbit.Option{
			"durable":    true,
			"autoDelete": false,
			"internal":   false,
			"noWait":     false,
		},
	)
	if err != nil {
		s.ChanMutex.Lock()
		s.Channel.Close()
		s.ChanMutex.Unlock()
		s.ConnMutex.Lock()
		s.Conn.Close()
		s.ConnMutex.Unlock()
		return err
	}
	log.Debugf("Submitter established connection to %s", s.URL)

	return nil
}

// MakeAMQPSubmitterWithReconnector creates a new submitter connected to a
// RabbitMQ server at the given URL, using the reconnector function as a means
// to Dial() in order to obtain a Connection object.
func MakeAMQPSubmitterWithReconnector(amqpURI string, amqpUser string,
	amqpPass string, amqpExch string, verbose bool,
	reconnector func(string) (wabbit.Conn, string, error)) (*AMQPSubmitter, error) {

	mySubmitter := &AMQPSubmitter{
		URL:              "amqp://" + amqpUser + ":" + amqpPass + "@" + amqpURI + "/",
		Verbose:          verbose,
		Reconnector:      reconnector,
		User:             amqpUser,
		Exchange:         amqpExch,
		StopReconnection: make(chan bool),
	}
	if verbose {
		log.Debugf("Initial connection to %s...", mySubmitter.URL)
	}

	mySubmitter.ErrorChan = make(chan wabbit.Error)
	err := mySubmitter.connect()
	if err != nil {
		return nil, err
	}
	mySubmitter.Conn.NotifyClose(mySubmitter.ErrorChan)

	go reconnectOnFailure(mySubmitter)

	return mySubmitter, nil
}

// Submit sends the jsonData payload via the registered RabbitMQ connection.
func (s *AMQPSubmitter) Submit(jsonData []byte) error {
	s.ChanMutex.Lock()
	err := s.Channel.Publish(
		s.Exchange,   // exchange
		"nightwatch", // routing key
		jsonData,
		wabbit.Option{
			"contentType": "application/json",
			"headers": origamqp.Table{
				"sensor_id": SensorID,
			},
		})
	s.ChanMutex.Unlock()
	if err == nil {
		if s.Verbose {
			log.Debugf("RabbitMQ submission (%s) successful", s.URL)
		}
	} else {
		log.Warnf("RabbitMQ submission not successful: %s", err.Error())
	}
	return err
}

// Finish cleans up the RMQ connection.
func (s *AMQPSubmitter) Finish() {
	close(s.StopReconnection)
	if s.Verbose {
		log.Debugf("Submitter closing connection...")
	}
}

// DummySubmitter is a Submitter that just logs data to a logger.
type DummySubmitter struct {
	l *log.Entry
}

// MakeDummySubmitter returns a new DummySubmitter.
func MakeDummySubmitter() *DummySubmitter {
	ds := &DummySubmitter{}
	ds.l = log.WithFields(log.Fields{
		"submitter": "dummy",
	})
	return ds
}

// Submit just logs the JSON data to the given logger.
func (s *DummySubmitter) Submit(jsonData []byte) error {
	s.l.Info(string(jsonData[:]))
	return nil
}

// Finish is a no-op in this implementation.
func (s *DummySubmitter) Finish() {}
