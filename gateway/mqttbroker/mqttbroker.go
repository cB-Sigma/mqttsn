// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package mqttbroker connects the MQTT-SN gateway to an MQTT 5 broker with
// Eclipse Paho's Go client (github.com/eclipse/paho.golang). Transparent
// mode opens one MQTT connection per MQTT-SN client, with the client's
// will as its MQTT will, so the broker sees each device; aggregating mode
// shares one connection, counts references to broker subscriptions and
// routes received messages to the clients whose filters match.
// Connections reconnect by themselves and restore their subscriptions.
package mqttbroker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"

	"github.com/cB-Sigma/mqttsn/gateway"
)

// Options configure the broker connection.
type Options struct {
	// URL is mqtt://host:port or mqtts://host:port.
	URL string
	// ClientID is the gateway's own connection (default "mqttsn-gateway").
	ClientID string
	// Prefix goes before each MQTT-SN client ID on its own connection
	// (transparent mode).
	Prefix             string
	Username, Password string
	TLS                *tls.Config
	// Aggregating shares one connection among all clients.
	Aggregating bool
	// KeepAlive of the MQTT connections in seconds (default 30).
	KeepAlive uint16
}

// Broker is a gateway.Broker on an MQTT 5 broker.
type Broker struct {
	o   Options
	u   *url.URL
	own *conn

	mu    sync.Mutex
	refs  map[string]int
	links map[*aggLink]struct{}
}

// Dial connects the gateway's own connection.
func Dial(ctx context.Context, o Options) (*Broker, error) {
	u, err := url.Parse(o.URL)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "tcp":
		u.Scheme = "mqtt"
	case "ssl", "tls":
		u.Scheme = "mqtts"
	}
	if u.Port() == "" {
		if u.Scheme == "mqtts" {
			u.Host += ":8883"
		} else {
			u.Host += ":1883"
		}
	}
	if o.ClientID == "" {
		o.ClientID = "mqttsn-gateway"
	}
	if o.KeepAlive == 0 {
		o.KeepAlive = 30
	}
	b := &Broker{o: o, u: u, refs: map[string]int{}, links: map[*aggLink]struct{}{}}
	var route func(gateway.Delivery)
	if o.Aggregating {
		route = b.route
	}
	if b.own, err = b.dial(ctx, o.ClientID, nil, route); err != nil {
		return nil, err
	}
	return b, nil
}

// Close ends the gateway's own connection.
func (b *Broker) Close() { b.own.close() }

// Connected implements gateway.Broker.
func (b *Broker) Connected() bool { return b.own.up.Load() }

// Publish implements gateway.Broker.
func (b *Broker) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	return b.own.Publish(ctx, topic, payload, qos, retain)
}

// Open implements gateway.Broker.
func (b *Broker) Open(ctx context.Context, clientID string, w *gateway.Will, deliver func(gateway.Delivery)) (gateway.Link, error) {
	if !b.o.Aggregating {
		return b.dial(ctx, b.o.Prefix+clientID, w, deliver)
	}
	l := &aggLink{b: b, deliver: deliver, subs: map[string]byte{}}
	b.mu.Lock()
	b.links[l] = struct{}{}
	b.mu.Unlock()
	return l, nil
}

// conn is a reconnecting MQTT 5 connection that restores its subscriptions.
type conn struct {
	cm     *autopaho.ConnectionManager
	cancel context.CancelFunc
	up     atomic.Bool
	mu     sync.Mutex
	subs   map[string]byte
}

func (b *Broker) dial(ctx context.Context, clientID string, w *gateway.Will, deliver func(gateway.Delivery)) (*conn, error) {
	cctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c := &conn{cancel: cancel, subs: map[string]byte{}}
	cfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{b.u},
		TlsCfg:                        b.o.TLS,
		KeepAlive:                     b.o.KeepAlive,
		CleanStartOnInitialConnection: true,
		ConnectTimeout:                10 * time.Second,
		ConnectUsername:               b.o.Username,
		OnConnectionUp: func(cm *autopaho.ConnectionManager, _ *paho.Connack) {
			c.up.Store(true)
			go c.resubscribe(cctx, cm)
		},
		OnConnectionDown: func() bool { c.up.Store(false); return true },
		ClientConfig: paho.ClientConfig{
			ClientID: clientID,
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(pr paho.PublishReceived) (bool, error) {
					if deliver != nil {
						deliver(gateway.Delivery{Topic: pr.Packet.Topic, Payload: pr.Packet.Payload, QoS: pr.Packet.QoS, Retain: pr.Packet.Retain})
					}
					return true, nil
				},
			},
		},
	}
	if b.o.Password != "" {
		cfg.ConnectPassword = []byte(b.o.Password)
	}
	if w != nil {
		cfg.WillMessage = &paho.WillMessage{Topic: w.Topic, Payload: w.Payload, QoS: w.QoS, Retain: w.Retain}
	}
	cm, err := autopaho.NewConnection(cctx, cfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("MQTT broker %s: %w", b.o.URL, err)
	}
	c.cm = cm
	actx, acancel := context.WithTimeout(ctx, 10*time.Second)
	defer acancel()
	if err := cm.AwaitConnection(actx); err != nil {
		c.close()
		return nil, fmt.Errorf("MQTT broker %s: %w", b.o.URL, err)
	}
	return c, nil
}

func (c *conn) resubscribe(ctx context.Context, cm *autopaho.ConnectionManager) {
	c.mu.Lock()
	s := &paho.Subscribe{}
	for f, q := range c.subs {
		s.Subscriptions = append(s.Subscriptions, paho.SubscribeOptions{Topic: f, QoS: q})
	}
	c.mu.Unlock()
	if len(s.Subscriptions) == 0 {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, _ = cm.Subscribe(sctx, s)
}

// Publish implements gateway.Link.
func (c *conn) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.cm.AwaitConnection(pctx); err != nil {
		return fmt.Errorf("not connected to the MQTT broker")
	}
	if _, err := c.cm.Publish(pctx, &paho.Publish{Topic: topic, QoS: qos, Retain: retain, Payload: payload}); err != nil {
		return fmt.Errorf("publishing to %s: %w", topic, err)
	}
	return nil
}

// Subscribe implements gateway.Link.
func (c *conn) Subscribe(ctx context.Context, filter string, qos byte) error {
	c.mu.Lock()
	c.subs[filter] = qos
	c.mu.Unlock()
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.cm.AwaitConnection(sctx); err != nil {
		return fmt.Errorf("not connected to the MQTT broker")
	}
	ack, err := c.cm.Subscribe(sctx, &paho.Subscribe{Subscriptions: []paho.SubscribeOptions{{Topic: filter, QoS: qos}}})
	if err != nil {
		return err
	}
	if len(ack.Reasons) > 0 && ack.Reasons[0] >= 0x80 {
		c.mu.Lock()
		delete(c.subs, filter)
		c.mu.Unlock()
		return fmt.Errorf("the broker refused the subscription to %s (reason %d)", filter, ack.Reasons[0])
	}
	return nil
}

// Unsubscribe implements gateway.Link.
func (c *conn) Unsubscribe(ctx context.Context, filter string) error {
	c.mu.Lock()
	delete(c.subs, filter)
	c.mu.Unlock()
	uctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.cm.AwaitConnection(uctx); err != nil {
		return nil
	}
	_, err := c.cm.Unsubscribe(uctx, &paho.Unsubscribe{Topics: []string{filter}})
	return err
}

// Close implements gateway.Link: a clean disconnect (no MQTT will).
func (c *conn) Close() { c.close() }

func (c *conn) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.cm.Disconnect(ctx)
	c.cancel()
}

// ---- aggregating ----

type aggLink struct {
	b       *Broker
	deliver func(gateway.Delivery)
	subs    map[string]byte
}

func (b *Broker) route(m gateway.Delivery) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for l := range b.links {
		best := -1
		for f, q := range l.subs {
			if gateway.TopicMatch(f, m.Topic) && int(q) > best {
				best = int(q)
			}
		}
		if best >= 0 {
			d := m
			d.QoS = min(m.QoS, byte(best))
			l.deliver(d)
		}
	}
}

func (b *Broker) release(filter string) bool {
	b.refs[filter]--
	if b.refs[filter] <= 0 {
		delete(b.refs, filter)
		return true
	}
	return false
}

func (l *aggLink) Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	return l.b.own.Publish(ctx, topic, payload, qos, retain)
}

func (l *aggLink) Subscribe(ctx context.Context, filter string, qos byte) error {
	b := l.b
	b.mu.Lock()
	_, had := l.subs[filter]
	l.subs[filter] = qos
	first := false
	if !had {
		b.refs[filter]++
		first = b.refs[filter] == 1
	}
	b.mu.Unlock()
	if first {
		// QoS 2 on the broker; each client gets what it asked for.
		if err := b.own.Subscribe(ctx, filter, 2); err != nil {
			b.mu.Lock()
			delete(l.subs, filter)
			b.release(filter)
			b.mu.Unlock()
			return err
		}
	}
	return nil
}

func (l *aggLink) Unsubscribe(ctx context.Context, filter string) error {
	b := l.b
	b.mu.Lock()
	_, had := l.subs[filter]
	delete(l.subs, filter)
	last := had && b.release(filter)
	b.mu.Unlock()
	if last {
		return b.own.Unsubscribe(ctx, filter)
	}
	return nil
}

func (l *aggLink) Close() {
	b := l.b
	b.mu.Lock()
	delete(b.links, l)
	var gone []string
	for f := range l.subs {
		if b.release(f) {
			gone = append(gone, f)
		}
	}
	l.subs = map[string]byte{}
	b.mu.Unlock()
	for _, f := range gone {
		_ = b.own.Unsubscribe(context.Background(), f)
	}
}
