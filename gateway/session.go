// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type state int

const (
	stConnecting state = iota // CONNECT with the will flag: waiting for WILLTOPIC / WILLMSG
	stActive
	stAsleep
	stAwake // woken by PINGREQ: receiving queued messages until PINGRESP
)

type evKind int

const (
	evPacket evKind = iota
)

type event struct {
	kind evKind
	msg  *Message // MQTT-SN 1.2
	// prev is the address a CONNECT took the session over from, if any.
	prev net.Addr
}

// client is a session of either protocol version, as the driver sees it.
type client interface {
	id() string
	version() byte
	getAddr() net.Addr
	setAddr(net.Addr)
	isDone() bool
	isAsleep() bool
	// isConnected is false for a 2.0 session kept after its virtual
	// connection ended (session expiry).
	isConnected() bool
	post(ctx context.Context, e event) bool
	// replace ends the session because another took its place (its
	// address, or its client ID in the other protocol version). It takes
	// effect at once: isDone is true and post refuses packets before the
	// session's loop has ended it, so a CONNECT that follows starts a new
	// session instead of being handed to the ending one.
	replace()
	doneCh() <-chan struct{}
}

// subInfo is one of the client's subscriptions.
type subInfo struct {
	qos byte
	typ byte // TopicNormal (by name, maybe a wildcard), TopicPredefined or TopicShort
}

// outItem is a message from the gateway to the client: a REGISTER or a
// PUBLISH. Publishes are queued in order; one message needing an
// acknowledgement is in flight at a time. A REGISTER is made just before
// a publish on a normal topic ID the client does not know yet.
type outItem struct {
	register bool
	retried  bool // re-registered once after "invalid topic ID"
	topic    string
	topicID  uint16
	idType   byte
	qos      byte
	retain   bool
	data     []byte

	msgID     uint16
	stage     int // QoS 2: 0 waiting PUBREC, 1 waiting PUBCOMP
	sentAt    time.Time
	tries     int
	congested int // "rejected: congestion" answers so far
}

// session is one MQTT-SN client. Its state belongs to its goroutine; the
// driver only posts events to it and reads the fields under mu.
type session struct {
	d        *driver
	clientID string
	in       chan event
	dl       chan inbound
	done     chan struct{}
	closing  atomic.Bool
	// replaced is closed by replace; replacing is set with it.
	replaced    chan struct{}
	replaceOnce sync.Once
	replacing   atomic.Bool

	mu     sync.Mutex
	addr   net.Addr
	asleep bool

	// owned by run
	st         state
	keepAlive  time.Duration
	sleepFor   time.Duration
	lastHeard  time.Time
	cleanStart bool
	will       *will
	lnk        link
	names      map[uint16]string // normal topic ID → name
	ids        map[string]uint16 // name → normal topic ID
	known      map[uint16]bool   // normal topic IDs the client has confirmed (REGISTER, REGACK, SUBACK)
	refused    map[string]bool   // topic names whose REGISTER the client rejected (clause 6.10)
	nextTopic  uint16
	subs       map[string]subInfo
	qos2In     map[uint16]bool
	queue      []*outItem
	inflight   *outItem
	holdUntil  time.Time // no publishes before this (the client was congested)
	nextMsg    uint16
	pingOwed   bool
}

func newSession(d *driver, clientID string, addr net.Addr) *session {
	s := &session{
		d: d, clientID: clientID, addr: addr,
		in: make(chan event, 64), dl: make(chan inbound, 1024), done: make(chan struct{}), replaced: make(chan struct{}),
		lastHeard: time.Now(),
	}
	s.reset()
	return s
}

func (s *session) replace() {
	s.replacing.Store(true)
	s.replaceOnce.Do(func() { close(s.replaced) })
}

func (s *session) reset() {
	s.names, s.ids, s.nextTopic = map[uint16]string{}, map[string]uint16{}, 0
	s.known, s.refused = map[uint16]bool{}, map[string]bool{}
	s.subs, s.qos2In = map[string]subInfo{}, map[uint16]bool{}
	s.queue, s.inflight = nil, nil
}

func (s *session) getAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

func (s *session) setAddr(a net.Addr) {
	s.mu.Lock()
	s.addr = a
	s.mu.Unlock()
}

func (s *session) isAsleep() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asleep
}

func (s *session) isDone() bool { return s.closing.Load() || s.replacing.Load() }

func (s *session) id() string              { return s.clientID }
func (s *session) version() byte           { return ProtocolID }
func (s *session) isConnected() bool       { return true }
func (s *session) doneCh() <-chan struct{} { return s.done }

func (s *session) setState(st state) {
	s.st = st
	s.mu.Lock()
	changed := s.asleep != (st == stAsleep || st == stAwake)
	s.asleep = st == stAsleep || st == stAwake
	s.mu.Unlock()
	if changed {
		s.d.changed()
	}
}

// post hands an event to the session; false means it has ended.
func (s *session) post(ctx context.Context, e event) bool {
	if s.isDone() {
		return false
	}
	select {
	case s.in <- e:
	case <-s.done:
		return false
	case <-ctx.Done():
	default:
		// A full queue drops the datagram, as the network could have.
	}
	return true
}

func (s *session) send(m *Message) { s.d.send(s.getAddr(), m) }

func (s *session) deliver(m inbound) {
	select {
	case s.dl <- m:
	default:
		s.d.h.Warn("mqttsn.queueFull", s.clientID, "maxQueued",
			"A message for the client was dropped because its queue is full; raise maxQueued to hold more.", m.topic)
	}
}

func (s *session) run(ctx context.Context) {
	defer close(s.done)
	defer s.d.remove(s)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.end(false, "")
			return
		case <-s.replaced:
			s.end(false, "disconnected")
			return
		case e := <-s.in:
			s.lastHeard = time.Now()
			if !s.handle(ctx, e.msg) {
				return
			}
		case m := <-s.dl:
			s.enqueue(m)
			s.pump()
		case now := <-tick.C:
			if s.expired(now) {
				s.d.h.Log().Info("MQTT-SN client lost", "client", s.clientID)
				s.end(true, "lost")
				return
			}
			s.retransmit(now)
			if s.inflight == nil && !s.holdUntil.IsZero() && !now.Before(s.holdUntil) {
				s.pump()
			}
		}
	}
}

func (s *session) expired(now time.Time) bool {
	var d time.Duration
	switch s.st {
	case stConnecting:
		d = max(s.keepAlive, 20*time.Second)
	case stActive:
		d = s.keepAlive
	case stAsleep, stAwake:
		d = s.sleepFor
	}
	return d > 0 && now.Sub(s.lastHeard) > lostAfter(d)
}

// lostAfter is how long a client may stay silent for a keep-alive or sleep
// duration d: 50% more up to a minute, 10% more above (clause 7.2).
func lostAfter(d time.Duration) time.Duration {
	if d > time.Minute {
		return d * 11 / 10
	}
	return d * 3 / 2
}

// activeWill is the will to publish or hand to the broker: nil until the
// client has given a will topic.
func (s *session) activeWill() *will {
	if s.will == nil || s.will.topic == "" {
		return nil
	}
	return s.will
}

// end closes the session: with lost, the client's will is published.
func (s *session) end(lost bool, why string) {
	s.closing.Store(true)
	if w := s.activeWill(); lost && w != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var err error
		if s.lnk != nil {
			err = s.lnk.publish(ctx, w.topic, w.msg, w.qos, w.retain)
		} else {
			err = s.d.up.publish(ctx, w.topic, w.msg, w.qos, w.retain)
		}
		cancel()
		if err != nil {
			s.d.h.Warn("mqttsn.willNotPublished", s.clientID, "",
				"The client's will was not published to the broker.", w.topic+": "+err.Error())
		}
	}
	if s.lnk != nil {
		s.lnk.close()
		s.lnk = nil
	}
	if why != "" {
		s.d.event(why, s)
	}
}

// handle processes one message from the client; false ends the session.
func (s *session) handle(ctx context.Context, m *Message) bool {
	if s.st == stConnecting {
		switch m.Type {
		case CONNECT, WILLTOPIC, WILLMSG, DISCONNECT:
		default:
			return true
		}
	}
	switch m.Type {
	case CONNECT:
		// The ProtocolId was checked by driver.connectAllowed.
		s.keepAlive = time.Duration(m.Duration) * time.Second
		s.cleanStart = m.Flags.CleanSession
		if s.cleanStart {
			// Clause 6.3: a clean session drops subscriptions and will.
			if s.lnk != nil {
				s.lnk.close()
				s.lnk = nil
			}
			s.reset()
			s.will = nil
		} else {
			// Clause 6.10: after a reconnect the gateway registers each
			// topic again before publishing on it.
			s.known = map[uint16]bool{}
		}
		if m.Flags.Will {
			s.setState(stConnecting)
			s.send(&Message{Type: WILLTOPICREQ})
			return true
		}
		return s.finishConnect(ctx)
	case WILLTOPIC:
		if s.st != stConnecting {
			return true
		}
		if m.TopicName == "" {
			s.will = nil
			return s.finishConnect(ctx)
		}
		s.will = &will{topic: m.TopicName, qos: clampQoS(m.Flags.QoS), retain: m.Flags.Retain}
		s.send(&Message{Type: WILLMSGREQ})
	case WILLMSG:
		if s.st != stConnecting || s.will == nil {
			return true
		}
		s.will.msg = m.Data
		return s.finishConnect(ctx)
	case REGISTER:
		if m.TopicName == "" || strings.ContainsAny(m.TopicName, "+#") {
			s.d.h.Warn("mqttsn.registerRefused", s.clientID, "",
				"A REGISTER for an empty topic name or one with wildcards was rejected; a client publishes only on topic names.", m.TopicName)
			s.send(&Message{Type: REGACK, MsgID: m.MsgID, ReturnCode: RejectedNotSupp})
			return true
		}
		id := s.topicID(m.TopicName)
		s.known[id] = true
		s.send(&Message{Type: REGACK, TopicID: id, MsgID: m.MsgID, ReturnCode: Accepted})
	case REGACK:
		if it := s.inflight; it != nil && it.register && it.msgID == m.MsgID {
			s.inflight = nil
			if m.ReturnCode == Accepted {
				s.known[it.topicID] = true
			} else {
				s.refuse(ctx, it.topic, it.topicID)
			}
			s.pump()
		}
	case PUBLISH:
		s.publish(ctx, m)
	case PUBREL:
		delete(s.qos2In, m.MsgID)
		s.send(&Message{Type: PUBCOMP, MsgID: m.MsgID})
	case PUBACK:
		// Clause 6.10: "invalid topic ID" from the client makes the
		// gateway register the topic again; a PUBACK with a rejection
		// also ends a QoS 2 exchange.
		it := s.inflight
		if m.ReturnCode == RejectedTopicID && (it == nil || it.idType == TopicNormal) {
			delete(s.known, m.TopicID)
		}
		if it != nil && !it.register && it.msgID == m.MsgID && (it.qos == 1 || it.qos == 2 && it.stage == 0 && m.ReturnCode != Accepted) {
			s.inflight = nil
			if m.ReturnCode == RejectedTopicID && it.idType == TopicNormal && !it.retried {
				it.retried, it.tries, it.stage = true, 0, 0
				s.queue = append([]*outItem{it}, s.queue...)
			}
			if m.ReturnCode == RejectedCongested {
				// The client is short of resources now: the message goes
				// again, first, after a back-off that doubles each time.
				if it.congested < s.d.s.Retries {
					it.congested++
					it.tries, it.stage = 0, 0
					s.queue = append([]*outItem{it}, s.queue...)
					s.holdUntil = time.Now().Add(s.d.s.Retry.D() << min(it.congested-1, 6))
				} else {
					s.d.h.Warn("mqttsn.notAcknowledged", s.clientID, "retries",
						"The client answered a message with congestion after retries back-offs; it was dropped.", it.topic)
				}
			}
			s.pump()
		}
	case PUBREC:
		if it := s.inflight; it != nil && !it.register && it.qos == 2 && it.msgID == m.MsgID {
			it.stage, it.sentAt, it.tries = 1, time.Now(), 0
			s.send(&Message{Type: PUBREL, MsgID: m.MsgID})
		}
	case PUBCOMP:
		if it := s.inflight; it != nil && !it.register && it.qos == 2 && it.stage == 1 && it.msgID == m.MsgID {
			s.inflight = nil
			s.pump()
		}
	case SUBSCRIBE:
		s.subscribe(ctx, m)
	case UNSUBSCRIBE:
		if name, _, ok := s.filterOf(m); ok && s.lnk != nil {
			if err := s.lnk.unsubscribe(ctx, name); err != nil {
				s.d.h.Log().Warn("MQTT unsubscribe failed", "client", s.clientID, "topic", name, "error", err)
			}
			delete(s.subs, name)
		}
		s.send(&Message{Type: UNSUBACK, MsgID: m.MsgID})
	case PINGREQ:
		if s.st == stAsleep {
			s.setState(stAwake)
			s.d.event("awake", s)
			s.pingOwed = true
			s.pump()
			return true
		}
		if s.st == stAwake {
			s.pingOwed = true
			s.pump()
			return true
		}
		s.send(&Message{Type: PINGRESP})
	case DISCONNECT:
		s.send(&Message{Type: DISCONNECT})
		if m.HasDuration && m.Duration > 0 && s.st != stConnecting {
			s.sleepFor = time.Duration(m.Duration) * time.Second
			s.setState(stAsleep)
			s.d.event("asleep", s)
			return true
		}
		s.end(false, "disconnected")
		return false
	case WILLTOPICUPD:
		if m.TopicName == "" {
			s.will = nil
		} else {
			var msg []byte
			if s.will != nil {
				msg = s.will.msg
			}
			s.will = &will{topic: m.TopicName, msg: msg, qos: clampQoS(m.Flags.QoS), retain: m.Flags.Retain}
		}
		s.send(&Message{Type: WILLTOPICRESP, ReturnCode: Accepted})
	case WILLMSGUPD:
		// Clause 6.4: independent of WILLTOPICUPD; a message without a
		// topic is kept until a topic arrives.
		if s.will == nil {
			s.will = &will{}
		}
		s.will.msg = m.Data
		s.send(&Message{Type: WILLMSGRESP, ReturnCode: Accepted})
	}
	return true
}

func (s *session) finishConnect(ctx context.Context) bool {
	if s.lnk == nil {
		l, err := s.d.up.open(ctx, s.clientID, s.activeWill(), nil, s.deliver)
		if err != nil {
			s.d.h.Warn("mqttsn.noBrokerConnection", s.clientID, "broker",
				"A client was refused (congestion) because its MQTT connection to the broker could not be opened.", err.Error())
			s.send(&Message{Type: CONNACK, ReturnCode: RejectedCongested})
			s.end(false, "")
			return false
		}
		s.lnk = l
	}
	s.setState(stActive)
	s.send(&Message{Type: CONNACK, ReturnCode: Accepted})
	s.d.event("connected", s)
	s.pump()
	return true
}

func clampQoS(q int8) byte {
	if q < 0 {
		return 0
	}
	return byte(min(q, 2))
}

// topicID returns the client's normal topic ID for name, assigning one.
func (s *session) topicID(name string) uint16 {
	if id, ok := s.ids[name]; ok {
		return id
	}
	for {
		s.nextTopic++
		if s.nextTopic == 0 || s.nextTopic == 0xFFFF {
			s.nextTopic = 1
		}
		if _, used := s.names[s.nextTopic]; !used {
			break
		}
	}
	s.ids[name], s.names[s.nextTopic] = s.nextTopic, name
	return s.nextTopic
}

// forget drops a normal topic ID and the publishes queued on it.
func (s *session) forget(name string, id uint16) {
	delete(s.ids, name)
	delete(s.names, id)
	delete(s.known, id)
	q := s.queue[:0]
	for _, it := range s.queue {
		if !it.register && it.idType == TopicNormal && it.topic == name {
			continue
		}
		q = append(q, it)
	}
	s.queue = q
}

// refuse handles a REGACK rejecting the gateway's REGISTER: like an
// unsubscribe from that topic name (clause 6.10). A subscription by that
// exact name ends; under a wildcard the name is skipped until the client
// subscribes again.
func (s *session) refuse(ctx context.Context, name string, id uint16) {
	s.forget(name, id)
	if sub, ok := s.subs[name]; ok && sub.typ == TopicNormal && s.lnk != nil {
		if err := s.lnk.unsubscribe(ctx, name); err != nil {
			s.d.h.Log().Warn("MQTT unsubscribe failed", "client", s.clientID, "topic", name, "error", err)
		}
		delete(s.subs, name)
		return
	}
	s.refused[name] = true
}

func (s *session) topicOf(m *Message) string {
	switch m.Flags.TopicIDType {
	case TopicNormal:
		return s.names[m.TopicID]
	case TopicPredefined:
		return s.d.predefined(m.TopicID, s.clientID)
	case TopicShort:
		return ShortName(m.TopicID)
	}
	return ""
}

func (s *session) publish(ctx context.Context, m *Message) {
	topic := s.topicOf(m)
	if topic == "" {
		if m.Flags.TopicIDType == TopicNormal {
			// The client re-registers after "invalid topic ID" (clause 6.10).
			s.d.h.Warn("mqttsn.unknownTopicId", s.clientID, "",
				"A publish on a topic ID the gateway did not register was answered with \"invalid topic ID\"; the client registers the topic again.", fmt.Sprintf("topic ID %d", m.TopicID))
		} else if m.Flags.TopicIDType == TopicReserved {
			s.d.h.Warn("mqttsn.reservedTopicIdType", s.clientID, "",
				"A publish with the reserved topic ID type was rejected as not supported.", fmt.Sprintf("topic ID %d", m.TopicID))
		}
		if m.Flags.QoS >= 0 {
			rc := RejectedTopicID
			if m.Flags.TopicIDType == TopicReserved {
				rc = RejectedNotSupp
			}
			s.send(&Message{Type: PUBACK, TopicID: m.TopicID, MsgID: m.MsgID, ReturnCode: rc})
		}
		return
	}
	qos := clampQoS(m.Flags.QoS)
	if qos == 2 && s.qos2In[m.MsgID] {
		s.send(&Message{Type: PUBREC, MsgID: m.MsgID}) // a repeat: already forwarded
		return
	}
	var err error
	if s.lnk != nil {
		err = s.lnk.publish(ctx, topic, m.Data, qos, m.Flags.Retain)
	} else {
		err = s.d.up.publish(ctx, topic, m.Data, qos, m.Flags.Retain)
	}
	if err != nil {
		s.d.h.Warn("mqttsn.publishNotForwarded", s.clientID, "",
			"A publish was not forwarded to the broker; the client was told the gateway is congested.", topic+": "+err.Error())
		if qos > 0 {
			s.send(&Message{Type: PUBACK, TopicID: m.TopicID, MsgID: m.MsgID, ReturnCode: RejectedCongested})
		}
		return
	}
	switch qos {
	case 1:
		s.send(&Message{Type: PUBACK, TopicID: m.TopicID, MsgID: m.MsgID, ReturnCode: Accepted})
	case 2:
		s.qos2In[m.MsgID] = true
		s.send(&Message{Type: PUBREC, MsgID: m.MsgID})
	}
}

// filterOf is the MQTT filter a SUBSCRIBE or UNSUBSCRIBE names.
func (s *session) filterOf(m *Message) (string, byte, bool) {
	switch m.Flags.TopicIDType {
	case TopicNormal:
		return m.TopicName, TopicNormal, m.TopicName != ""
	case TopicPredefined:
		n, ok := s.d.pre[m.TopicID]
		return n, TopicPredefined, ok
	case TopicShort:
		return ShortName(m.TopicID), TopicShort, true
	}
	return "", 0, false
}

func (s *session) subscribe(ctx context.Context, m *Message) {
	qos := clampQoS(m.Flags.QoS)
	ack := &Message{Type: SUBACK, MsgID: m.MsgID, Flags: Flags{QoS: int8(qos)}}
	name, typ, ok := s.filterOf(m)
	if !ok {
		s.d.h.Warn("mqttsn.subscribeRefused", s.clientID, "predefinedTopics",
			"A SUBSCRIBE to an empty topic name, an unknown predefined topic ID or the reserved topic ID type was rejected.", fmt.Sprintf("topic ID type %d, ID %d", m.Flags.TopicIDType, m.TopicID))
		ack.ReturnCode = RejectedTopicID
		if m.Flags.TopicIDType == TopicNormal || m.Flags.TopicIDType == TopicReserved {
			ack.ReturnCode = RejectedNotSupp
		}
		s.send(ack)
		return
	}
	if s.lnk == nil {
		ack.ReturnCode = RejectedCongested
		s.send(ack)
		return
	}
	if err := s.lnk.subscribe(ctx, name, subOpts{qos: qos}); err != nil {
		s.d.h.Warn("mqttsn.subscribeFailed", s.clientID, "",
			"The broker did not accept a client's subscription; the client was told the gateway is congested.", name+": "+err.Error())
		ack.ReturnCode = RejectedCongested
		s.send(ack)
		return
	}
	s.subs[name] = subInfo{qos: qos, typ: typ}
	for r := range s.refused {
		if TopicMatch(name, r) {
			delete(s.refused, r)
		}
	}
	switch typ {
	case TopicNormal:
		if !strings.ContainsAny(name, "+#") {
			ack.TopicID = s.topicID(name)
			s.known[ack.TopicID] = true
		}
	case TopicPredefined:
		ack.TopicID = m.TopicID
	}
	s.send(ack)
}

// enqueue turns a broker message into a publish for the client.
func (s *session) enqueue(m inbound) {
	if s.refused[m.topic] {
		return
	}
	// Clause 6.10: a message too long for PUBLISH (or its topic name for
	// REGISTER) is dropped without telling the client.
	if len(m.payload)+9 > MaxLength || len(m.topic)+8 > MaxLength {
		s.d.h.Warn("mqttsn.messageTooLong", s.clientID, "",
			"A message too long for an MQTT-SN PUBLISH was dropped (MQTT-SN 1.2 clause 6.10).", fmt.Sprintf("%s: %d bytes", m.topic, len(m.payload)))
		return
	}
	it := &outItem{topic: m.topic, qos: min(m.qos, 2), retain: m.retain, data: m.payload}
	if sub, ok := s.subs[m.topic]; ok && sub.typ == TopicShort && len(m.topic) == 2 {
		it.idType, it.topicID = TopicShort, uint16(m.topic[0])<<8|uint16(m.topic[1])
	} else if id, ok := s.d.preN[m.topic]; ok && s.subs[m.topic].typ == TopicPredefined {
		it.idType, it.topicID = TopicPredefined, id
	} else {
		it.idType, it.topicID = TopicNormal, s.topicID(m.topic)
	}
	// Bound the queue: drop the oldest publishes first.
	for n := s.countPublishes(); n >= s.d.s.MaxQueued; n-- {
		for i, q := range s.queue {
			if !q.register {
				s.queue = append(s.queue[:i], s.queue[i+1:]...)
				break
			}
		}
		s.d.h.Warn("mqttsn.queueFull", s.clientID, "maxQueued",
			"A message for the client was dropped because its queue is full; raise maxQueued to hold more.", "")
	}
	s.queue = append(s.queue, it)
}

func (s *session) countPublishes() int {
	n := 0
	for _, q := range s.queue {
		if !q.register {
			n++
		}
	}
	return n
}

func (s *session) msgID() uint16 {
	s.nextMsg++
	if s.nextMsg == 0 {
		s.nextMsg = 1
	}
	return s.nextMsg
}

func (s *session) sendItem(it *outItem, dup bool) {
	if it.register {
		s.send(&Message{Type: REGISTER, TopicID: it.topicID, MsgID: it.msgID, TopicName: it.topic})
		return
	}
	if it.stage == 1 {
		s.send(&Message{Type: PUBREL, MsgID: it.msgID})
		return
	}
	s.send(&Message{Type: PUBLISH, Flags: Flags{DUP: dup, QoS: int8(it.qos), Retain: it.retain, TopicIDType: it.idType},
		TopicID: it.topicID, MsgID: it.msgID, Data: it.data})
}

// pump sends queued items while nothing awaits an acknowledgement; a
// sleeping client gets nothing until it wakes.
func (s *session) pump() {
	if s.st == stAsleep || s.st == stConnecting {
		return
	}
	if !s.holdUntil.IsZero() {
		if time.Now().Before(s.holdUntil) {
			return
		}
		s.holdUntil = time.Time{}
	}
	for s.inflight == nil && len(s.queue) > 0 {
		it := s.queue[0]
		if !it.register && it.idType == TopicNormal {
			it.topicID = s.topicID(it.topic)
			if !s.known[it.topicID] {
				// Clause 6.10: REGISTER first; the publish waits for REGACK.
				reg := &outItem{register: true, topic: it.topic, topicID: it.topicID, msgID: s.msgID()}
				s.sendItem(reg, false)
				reg.sentAt = time.Now()
				s.inflight = reg
				break
			}
		}
		s.queue = s.queue[1:]
		if it.register || it.qos > 0 {
			it.msgID = s.msgID()
		}
		s.sendItem(it, false)
		if it.register || it.qos > 0 {
			it.sentAt = time.Now()
			s.inflight = it
		}
	}
	if s.st == stAwake && s.pingOwed && s.inflight == nil && len(s.queue) == 0 {
		s.pingOwed = false
		s.send(&Message{Type: PINGRESP})
		s.setState(stAsleep)
	}
}

func (s *session) retransmit(now time.Time) {
	it := s.inflight
	if it == nil || s.st == stAsleep || now.Sub(it.sentAt) < s.d.s.Retry.D() {
		return
	}
	if it.tries >= s.d.s.Retries {
		s.d.h.Warn("mqttsn.notAcknowledged", s.clientID, "retries",
			"The client did not acknowledge a message after retries retransmissions; it was dropped.", it.topic)
		s.inflight = nil
		if it.register {
			s.forget(it.topic, it.topicID)
		}
		s.pump()
		return
	}
	it.tries++
	it.sentAt = now
	s.sendItem(it, true)
}
