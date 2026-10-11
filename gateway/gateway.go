// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package gateway is an MQTT-SN 1.2 gateway: devices speak MQTT-SN over
// UDP (or any datagram transport, such as DTLS) and the gateway relays
// their publishes and subscriptions to an MQTT broker through a [Broker].
//
// It answers SEARCHGW with GWINFO and can send ADVERTISE; it accepts
// CONNECT with a will (WILLTOPICREQ, WILLMSGREQ, and the will updates),
// REGISTER in both directions, PUBLISH at QoS -1 to 2 on normal,
// predefined and short topic IDs, SUBSCRIBE and UNSUBSCRIBE with
// wildcards, PINGREQ, DISCONNECT and sleep: messages for a sleeping
// client are queued and delivered when it wakes with a PINGREQ carrying
// its client ID, PINGRESP after the last one. A client silent for its
// keep-alive or sleep duration plus 50% (plus 10% above one minute) is
// lost and its will published. Wireless nodes behind a forwarder
// (Encapsulated Messages) each get their own session.
//
// The session logic is that of SigmaM2M's MQTT-SN gateway, from which it
// was extracted; the MQTT side is an interface: [MemoryBroker] in process,
// or the mqttbroker package for an MQTT 5 broker.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	sn "github.com/cB-Sigma/mqttsn"
)

// Will is a client's last will as handed to the broker.
type Will struct {
	Topic   string
	Payload []byte
	QoS     byte
	Retain  bool
}

// Delivery is a message the broker has for a client.
type Delivery struct {
	Topic   string
	Payload []byte
	QoS     byte
	Retain  bool
}

// Broker is the MQTT side of the gateway.
type Broker interface {
	// Open gives a client its link to the broker; deliver must not block.
	// A broker may open one MQTT connection per client (transparent, the
	// will as its MQTT will) or share one (aggregating).
	Open(ctx context.Context, clientID string, will *Will, deliver func(Delivery)) (Link, error)
	// Publish sends a message as the gateway itself (QoS -1 publishes and
	// wills).
	Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error
	// Connected reports whether the broker can be reached (ADVERTISE is
	// sent only then).
	Connected() bool
}

// Link is one client's view of the broker.
type Link interface {
	Publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error
	Subscribe(ctx context.Context, filter string, qos byte) error
	Unsubscribe(ctx context.Context, filter string) error
	// Close ends the link without the broker publishing an MQTT will.
	Close()
}

// Event is something that happened to a client: "connected",
// "disconnected", "asleep", "awake" or "lost".
type Event struct {
	Kind     string
	ClientID string
	Addr     net.Addr
}

// Options configure a gateway.
type Options struct {
	// GatewayID is the GwId of GWINFO and ADVERTISE (default 1).
	GatewayID byte
	// Predefined maps predefined topic IDs to topic names.
	Predefined map[uint16]string
	// UnknownTopicPrefix receives publishes on predefined topic IDs not in
	// Predefined, as <prefix>/<ID>; empty refuses them.
	UnknownTopicPrefix string
	// MaxClients (default 1000) and MaxQueued messages per client (default
	// 100, the oldest dropped first).
	MaxClients, MaxQueued int
	// Retry is the retransmission interval towards clients (default 10s)
	// and Retries how often (default 3).
	Retry   time.Duration
	Retries int
	// Advertise sends ADVERTISE to this address (a broadcast address, say)
	// every AdvertiseInterval (default 15m) while the broker is connected.
	Advertise         string
	AdvertiseInterval time.Duration
	// Strict refuses CONNECTs with a ProtocolId other than 1 and an empty
	// or over-long client ID (accepted otherwise).
	Strict bool
	// OnEvent and OnWarn report client events and problems.
	OnEvent func(Event)
	OnWarn  func(code, subject, detail string)
	// Log receives debug output (default: discarded).
	Log *slog.Logger
}

// Gateway is an MQTT-SN 1.2 gateway.
type Gateway struct{ d *driver }

// New makes a gateway relaying to b.
func New(b Broker, o Options) *Gateway {
	if o.GatewayID == 0 {
		o.GatewayID = 1
	}
	if o.MaxClients <= 0 {
		o.MaxClients = 1000
	}
	if o.MaxQueued <= 0 {
		o.MaxQueued = 100
	}
	if o.Retry <= 0 {
		o.Retry = 10 * time.Second
	}
	if o.Retries <= 0 {
		o.Retries = 3
	}
	if o.AdvertiseInterval <= 0 {
		o.AdvertiseInterval = 15 * time.Minute
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	d := &driver{o: o, up: upstream{b}, byAddr: map[string]client{}, byClient: map[string]client{},
		pre: map[uint16]string{}, preN: map[string]uint16{}}
	d.s = settings{MaxQueued: o.MaxQueued, Retries: o.Retries, Retry: dur(o.Retry)}
	d.h = host{d}
	for id, n := range o.Predefined {
		d.pre[id], d.preN[n] = n, id
	}
	return &Gateway{d: d}
}

// ListenAndServe serves on a UDP address until ctx ends.
func (g *Gateway) ListenAndServe(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	return g.Serve(ctx, pc)
}

// Serve serves on a datagram connection until ctx ends (it then closes
// pc). Use dtls.Listen of this module for DTLS.
func (g *Gateway) Serve(ctx context.Context, pc net.PacketConn) error {
	d := g.d
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.mu.Lock()
	d.pc = pc
	d.mu.Unlock()
	go func() { <-ctx.Done(); _ = pc.Close() }()
	anon := make(chan *Message, 256)
	go d.anonymous(ctx, anon)
	if d.o.Advertise != "" {
		go d.advertising(ctx)
	}
	buf := make([]byte, 65536)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				d.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("mqttsn gateway: %w", err)
		}
		d.receive(ctx, addr, append([]byte(nil), buf[:n]...), anon)
	}
}

// Clients lists the connected client IDs and whether each is asleep.
func (g *Gateway) Clients() map[string]bool {
	d := g.d
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]bool{}
	for id, c := range d.byClient {
		if !c.isDone() {
			out[id] = c.isAsleep()
		}
	}
	return out
}

// ---- internals shaped like SigmaM2M's gateway, so the session code ports as is.

type dur time.Duration

func (d dur) D() time.Duration { return time.Duration(d) }

type settings struct {
	MaxQueued, Retries int
	Retry              dur
}

type host struct{ d *driver }

func (h host) Warn(code, subject, _ string, _ string, detail string) {
	if h.d.o.OnWarn != nil {
		h.d.o.OnWarn(code, subject, detail)
	}
}

func (h host) Log() *slog.Logger { return h.d.o.Log }

// will and inbound are the session's views of Will and Delivery.
type will struct {
	topic  string
	msg    []byte
	qos    byte
	retain bool
}

type inbound struct {
	topic   string
	payload []byte
	qos     byte
	retain  bool
}

type subOpts struct{ qos byte }

type upstream struct{ b Broker }

func (u upstream) open(ctx context.Context, id string, w *will, _ any, deliver func(inbound)) (link, error) {
	var bw *Will
	if w != nil {
		bw = &Will{Topic: w.topic, Payload: w.msg, QoS: w.qos, Retain: w.retain}
	}
	l, err := u.b.Open(ctx, id, bw, func(m Delivery) {
		deliver(inbound{topic: m.Topic, payload: m.Payload, qos: m.QoS, retain: m.Retain})
	})
	if err != nil {
		return nil, err
	}
	return linkOf{l}, nil
}

func (u upstream) publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	return u.b.Publish(ctx, topic, payload, qos, retain)
}

type link interface {
	publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error
	subscribe(ctx context.Context, filter string, o subOpts) error
	unsubscribe(ctx context.Context, filter string) error
	close()
}

type linkOf struct{ l Link }

func (l linkOf) publish(ctx context.Context, topic string, payload []byte, qos byte, retain bool) error {
	return l.l.Publish(ctx, topic, payload, qos, retain)
}
func (l linkOf) subscribe(ctx context.Context, f string, o subOpts) error {
	return l.l.Subscribe(ctx, f, o.qos)
}
func (l linkOf) unsubscribe(ctx context.Context, f string) error { return l.l.Unsubscribe(ctx, f) }
func (l linkOf) close()                                          { l.l.Close() }

type driver struct {
	o  Options
	s  settings
	h  host
	up upstream

	mu       sync.Mutex
	pc       net.PacketConn
	byAddr   map[string]client
	byClient map[string]client
	pre      map[uint16]string
	preN     map[string]uint16
	wg       sync.WaitGroup
}

func (d *driver) changed() {}

func (d *driver) event(kind string, s client) {
	if d.o.OnEvent != nil {
		d.o.OnEvent(Event{Kind: kind, ClientID: s.id(), Addr: s.getAddr()})
	}
}

func (d *driver) remove(s client) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.byClient[s.id()] == s {
		delete(d.byClient, s.id())
	}
	if a := s.getAddr().String(); d.byAddr[a] == s {
		delete(d.byAddr, a)
	}
}

func (d *driver) predefined(id uint16, client string) string {
	if n, ok := d.pre[id]; ok {
		return n
	}
	if d.o.UnknownTopicPrefix == "" {
		d.h.Warn("mqttsn.unknownTopicId", client, "", "", fmt.Sprintf("predefined topic ID %d", id))
		return ""
	}
	return fmt.Sprintf("%s/%d", d.o.UnknownTopicPrefix, id)
}

// forwardedAddr is a wireless node behind a forwarder: the forwarder's
// address and the node's ID key its session.
type forwardedAddr struct {
	forwarder net.Addr
	radius    byte
	node      []byte
}

func (a *forwardedAddr) Network() string { return a.forwarder.Network() }
func (a *forwardedAddr) String() string  { return fmt.Sprintf("%s/%x", a.forwarder, a.node) }

func (d *driver) send(addr net.Addr, m *Message) {
	out := m.Encode()
	if fa, ok := addr.(*forwardedAddr); ok {
		out, addr = sn.Encapsulate(fa.radius, fa.node, out), fa.forwarder
	}
	d.mu.Lock()
	pc := d.pc
	d.mu.Unlock()
	if pc == nil {
		return
	}
	if _, err := pc.WriteTo(out, addr); err != nil {
		d.o.Log.Debug("MQTT-SN send failed", "to", addr.String(), "error", err)
	}
}

func (d *driver) receive(ctx context.Context, addr net.Addr, b []byte, anon chan<- *Message) {
	if radius, node, inner, ok := sn.Decapsulate(b); ok {
		addr, b = &forwardedAddr{forwarder: addr, radius: radius, node: node}, inner
	}
	m, err := Decode(b)
	if err != nil {
		d.h.Warn("mqttsn.datagramUnreadable", addr.String(), "", "", err.Error())
		return
	}
	d.dispatch(ctx, addr, m, anon)
}

func (d *driver) connectAllowed(addr net.Addr, m *Message) bool {
	from := addr.String()
	if m.ProtocolID != ProtocolID {
		if d.o.Strict {
			d.h.Warn("mqttsn.connectRefused", from, "", "", fmt.Sprintf("ProtocolId %d", m.ProtocolID))
			return false
		}
		d.h.Warn("mqttsn.unknownProtocolId", from, "", "", fmt.Sprintf("ProtocolId %d accepted as 1.2", m.ProtocolID))
		m.ProtocolID = ProtocolID
	}
	if m.ClientID != "" && len(m.ClientID) <= 23 {
		return true
	}
	if d.o.Strict {
		d.h.Warn("mqttsn.connectRefused", from, "", "", fmt.Sprintf("client ID of %d characters", len(m.ClientID)))
		return false
	}
	if m.ClientID == "" {
		m.ClientID = "sn-" + from
	}
	return true
}

func (d *driver) dispatch(ctx context.Context, addr net.Addr, m *Message, anon chan<- *Message) {
	key := addr.String()
	switch m.Type {
	case SEARCHGW:
		d.send(addr, &Message{Type: GWINFO, GwID: d.o.GatewayID})
		return
	case sn.ADVERTISE, GWINFO:
		return // other gateways
	}
	d.mu.Lock()
	var s client
	if c := d.byAddr[key]; c != nil {
		s = c
	}
	switch {
	case m.Type == CONNECT:
		if !d.connectAllowed(addr, m) {
			d.mu.Unlock()
			d.send(addr, &Message{Type: CONNACK, ReturnCode: RejectedNotSupp})
			return
		}
		if prev := d.byClient[m.ClientID]; prev != nil && !prev.isDone() {
			if prev.getAddr().String() != key {
				if was := prev.getAddr().String(); d.byAddr[was] == prev {
					delete(d.byAddr, was)
				}
				if old := d.byAddr[key]; old != nil && old != prev {
					old.replace()
				}
				prev.setAddr(addr)
				d.byAddr[key] = prev
			}
			s = prev
		} else {
			if old := d.byAddr[key]; old != nil {
				old.replace()
			}
			if len(d.byClient) >= d.o.MaxClients {
				d.mu.Unlock()
				d.h.Warn("mqttsn.maxClients", m.ClientID, "", "", key)
				d.send(addr, &Message{Type: CONNACK, ReturnCode: RejectedCongested})
				return
			}
			ns := newSession(d, m.ClientID, addr)
			d.byAddr[key] = ns
			d.byClient[m.ClientID] = ns
			d.wg.Add(1)
			go func() { defer d.wg.Done(); ns.run(ctx) }()
			s = ns
		}
	case m.Type == PINGREQ && m.ClientID != "" && (s == nil || s.id() != m.ClientID):
		// A sleeping client waking up, possibly from a new address.
		prev := d.byClient[m.ClientID]
		if prev == nil || prev.isDone() {
			s = nil
			break
		}
		if was := prev.getAddr().String(); d.byAddr[was] == prev {
			delete(d.byAddr, was)
		}
		prev.setAddr(addr)
		d.byAddr[key] = prev
		s = prev
	}
	d.mu.Unlock()
	if s != nil && s.post(ctx, event{kind: evPacket, msg: m}) {
		return
	}
	switch {
	case m.Type == PUBLISH && m.Flags.QoS == -1:
		select {
		case anon <- m:
		default:
			d.h.Warn("mqttsn.busy", key, "", "", "QoS -1 publish dropped")
		}
	case m.Type == DISCONNECT, m.Type == PINGRESP:
	default:
		// Not connected: tell the client so it connects again.
		d.send(addr, &Message{Type: DISCONNECT})
	}
}

// anonymous forwards QoS -1 publishes (predefined and short topics only).
func (d *driver) anonymous(ctx context.Context, in <-chan *Message) {
	for {
		var m *Message
		select {
		case <-ctx.Done():
			return
		case m = <-in:
		}
		var topic string
		switch m.Flags.TopicIDType {
		case TopicPredefined:
			topic = d.predefined(m.TopicID, "")
		case TopicShort:
			topic = ShortName(m.TopicID)
		}
		if topic == "" {
			d.h.Warn("mqttsn.unknownTopicId", "", "", "", fmt.Sprintf("QoS -1 publish on topic ID %d", m.TopicID))
			continue
		}
		if err := d.up.publish(ctx, topic, m.Data, 0, m.Flags.Retain); err != nil {
			d.h.Warn("mqttsn.publishNotForwarded", "", "", "", topic+": "+err.Error())
		}
	}
}

func (d *driver) advertising(ctx context.Context) {
	to, err := net.ResolveUDPAddr("udp", d.o.Advertise)
	if err != nil {
		d.h.Warn("mqttsn.advertise", d.o.Advertise, "", "", err.Error())
		return
	}
	t := time.NewTicker(d.o.AdvertiseInterval)
	defer t.Stop()
	for {
		if d.up.b.Connected() {
			d.send(to, &Message{Type: sn.ADVERTISE, GwID: d.o.GatewayID, Duration: uint16(d.o.AdvertiseInterval / time.Second)})
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// TopicMatch reports whether an MQTT topic filter matches a topic name.
func TopicMatch(filter, topic string) bool {
	if strings.HasPrefix(topic, "$") && (strings.HasPrefix(filter, "+") || strings.HasPrefix(filter, "#")) {
		return false
	}
	f, n := strings.Split(filter, "/"), strings.Split(topic, "/")
	for i, p := range f {
		if p == "#" {
			return true
		}
		if i >= len(n) || (p != "+" && p != n[i]) {
			return false
		}
	}
	return len(f) == len(n)
}
