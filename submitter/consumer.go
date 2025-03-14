// Nightwatch
// Copyright (c) 2016, 2025, DCSO GmbH

package submitter

import (
	"fmt"

	"github.com/NeowayLabs/wabbit"
	"github.com/NeowayLabs/wabbit/amqptest"
	log "github.com/sirupsen/logrus"
)

// Consumer reads and processes messages from a fake RabbitMQ server.
type Consumer struct {
	conn     wabbit.Conn
	channel  wabbit.Channel
	tag      string
	done     chan error
	Callback func(wabbit.Delivery)
}

// NewConsumer creates a new consumer with the given properties. The callback
// function is called for each delivery accepted from a consumer channel.
func NewConsumer(amqpURI, exchange, exchangeType, queueName, key, ctag string, callback func(wabbit.Delivery)) (*Consumer, error) {
	var err error
	c := &Consumer{
		conn:     nil,
		channel:  nil,
		tag:      ctag,
		done:     make(chan error),
		Callback: callback,
	}

	log.Debugf("dialing %q", amqpURI)
	c.conn, err = amqptest.Dial(amqpURI)
	if err != nil {
		return nil, fmt.Errorf("dial: %s", err)
	}

	log.Debugf("got Connection, getting Channel")
	c.channel, err = c.conn.Channel()
	if err != nil {
		return nil, fmt.Errorf("channel: %s", err)
	}

	log.Debugf("got Channel, declaring Exchange (%q)", exchange)
	if err = c.channel.ExchangeDeclare(
		exchange,     // name of the exchange
		exchangeType, // type
		wabbit.Option{
			"durable":  true,
			"delete":   false,
			"internal": false,
			"noWait":   false,
		},
	); err != nil {
		return nil, fmt.Errorf("exchange declare: %s", err)
	}

	queue, err := c.channel.QueueDeclare(
		queueName, // name of the queue
		wabbit.Option{
			"durable":   true,
			"delete":    false,
			"exclusive": false,
			"noWait":    false,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("queue declare: %s", err)
	}

	log.Debugf("declared Queue (%q %d messages, %d consumers), binding to Exchange (key %q)",
		queue.Name(), queue.Messages(), queue.Consumers(), key)

	if err = c.channel.QueueBind(
		queue.Name(), // name of the queue
		key,          // bindingKey
		exchange,     // sourceExchange
		wabbit.Option{
			"noWait": false,
		},
	); err != nil {
		return nil, fmt.Errorf("queue bind: %s", err)
	}

	log.Debugf("Queue bound to Exchange, starting Consume (consumer tag %q)", c.tag)
	deliveries, err := c.channel.Consume(
		queue.Name(), // name
		c.tag,        // consumerTag,
		wabbit.Option{
			"exclusive": false,
			"noLocal":   false,
			"noWait":    false,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("queue consume: %s", err)
	}
	go handle(deliveries, c.done, c.Callback)

	return c, nil
}

// Shutdown shuts down a consumer, closing down its channels and connections.
func (c *Consumer) Shutdown() error {
	// will close() the deliveries channel
	if err := c.channel.Close(); err != nil {
		return fmt.Errorf("channel close failed: %s", err)
	}
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("AMQP connection close error: %s", err)
	}
	defer log.Debugf("AMQP shutdown OK")
	// wait for handle() to exit
	return <-c.done
}

func handle(deliveries <-chan wabbit.Delivery, done chan error, callback func(wabbit.Delivery)) {
	for d := range deliveries {
		log.Debugf(
			"got %dB delivery: [%v] %q",
			len(d.Body()),
			d.DeliveryTag(),
			d.Body(),
		)
		callback(d)
		d.Ack(false)
	}
	done <- nil
}
