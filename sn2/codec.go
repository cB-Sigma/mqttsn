// Package sn2 encodes and decodes MQTT-SN 2.0 packets, based on OASIS
// MQTT-SN 2.0 draft CSD01 (Committee Specification Draft 01, 05 February
// 2026). The draft is not an OASIS Standard yet; clause numbers below
// refer to it.
//
// MQTT-SN 2.0 keeps the 1.2 length header (one byte, or 0x01 and two
// bytes) but renumbers every packet type, moves the will into CONNECT,
// replaces short topic names with full topic names, adds packet
// identifiers to most packets, reason codes to every response, session
// expiry, AUTH, SLEEPREQ/SLEEPRESP, WAKEUP, PUBWOS and three envelopes.
// The package only lays packets out; behaviour lives in the gateway or
// client that uses it.
package sn2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Type is a packet type (clause 2.1.3).
type Type byte

// Packet types.
const (
	CONNECT     Type = 0x01
	CONNACK     Type = 0x02
	PUBLISH     Type = 0x03
	PUBACK      Type = 0x04
	PUBREC      Type = 0x05
	PUBREL      Type = 0x06
	PUBCOMP     Type = 0x07
	SUBSCRIBE   Type = 0x08
	SUBACK      Type = 0x09
	UNSUBSCRIBE Type = 0x0A
	UNSUBACK    Type = 0x0B
	PINGREQ     Type = 0x0C
	PINGRESP    Type = 0x0D
	DISCONNECT  Type = 0x0E
	AUTH        Type = 0x0F
	REGISTER    Type = 0x10
	REGACK      Type = 0x11
	PUBWOS      Type = 0x12
	SLEEPREQ    Type = 0x13
	SLEEPRESP   Type = 0x14
	WAKEUP      Type = 0x15
	ADVERTISE   Type = 0x16
	SEARCHGW    Type = 0x17
	GWINFO      Type = 0x18
	// Envelopes (clauses 3.17 to 3.19). Their Length covers the envelope
	// header only; the wrapped packet follows.
	ForwarderEncapsulation  Type = 0xFD
	ConnectionEncapsulation Type = 0xFE
	ProtectionEncapsulation Type = 0xFF
)

var names = map[Type]string{
	CONNECT: "CONNECT", CONNACK: "CONNACK", PUBLISH: "PUBLISH", PUBACK: "PUBACK", PUBREC: "PUBREC",
	PUBREL: "PUBREL", PUBCOMP: "PUBCOMP", SUBSCRIBE: "SUBSCRIBE", SUBACK: "SUBACK",
	UNSUBSCRIBE: "UNSUBSCRIBE", UNSUBACK: "UNSUBACK", PINGREQ: "PINGREQ", PINGRESP: "PINGRESP",
	DISCONNECT: "DISCONNECT", AUTH: "AUTH", REGISTER: "REGISTER", REGACK: "REGACK", PUBWOS: "PUBWOS",
	SLEEPREQ: "SLEEPREQ", SLEEPRESP: "SLEEPRESP", WAKEUP: "WAKEUP", ADVERTISE: "ADVERTISE",
	SEARCHGW: "SEARCHGW", GWINFO: "GWINFO", ForwarderEncapsulation: "FORWARDER-ENCAPSULATION",
	ConnectionEncapsulation: "CONNECTION-ENCAPSULATION", ProtectionEncapsulation: "PROTECTION-ENCAPSULATION",
}

func (t Type) String() string {
	if s, ok := names[t]; ok {
		return s
	}
	return fmt.Sprintf("0x%02X", byte(t))
}

// ProtocolVersion is the CONNECT Protocol Version of MQTT-SN 2.0 (clause 3.1.5).
const ProtocolVersion = 0x02

// Topic types (clause 2.4).
const (
	TopicSession    byte = 0 // a session topic alias
	TopicPredefined byte = 1 // a predefined topic alias
	TopicReserved   byte = 2
	TopicName       byte = 3 // a topic name or topic filter
)

// Reason is a reason code (clause 2.3); 0x80 and above are failures.
type Reason byte

// Reason codes the gateway uses or recognises.
const (
	Success                 Reason = 0x00
	GrantedQoS1             Reason = 0x01
	GrantedQoS2             Reason = 0x02
	DisconnectWithWill      Reason = 0x04
	NoSubscriptionExisted   Reason = 0x11
	ContinueAuthentication  Reason = 0x18
	ReAuthenticate          Reason = 0x19
	TopicAliasExists        Reason = 0x1A
	UnspecifiedError        Reason = 0x80
	MalformedPacket         Reason = 0x81
	ProtocolError           Reason = 0x82
	ImplementationError     Reason = 0x83
	UnsupportedVersion      Reason = 0x84
	ClientIDNotValid        Reason = 0x85
	BadUserNameOrPassword   Reason = 0x86
	NotAuthorized           Reason = 0x87
	ServerUnavailable       Reason = 0x88
	ServerBusy              Reason = 0x89
	ServerShuttingDown      Reason = 0x8B
	BadAuthenticationMethod Reason = 0x8C
	KeepAliveTimeout        Reason = 0x8D
	SessionTakenOver        Reason = 0x8E
	TopicFilterInvalid      Reason = 0x8F
	TopicNameInvalid        Reason = 0x90
	PacketIDNotFound        Reason = 0x92
	PacketTooLarge          Reason = 0x95
	QuotaExceeded           Reason = 0x97
	ProtectionNotSupported  Reason = 0xF2
	UnknownTopicAlias       Reason = 0xF0
	Congestion              Reason = 0xF1
	NoVirtualConnection     Reason = 0xF4
	ForwarderNotSupported   Reason = 0xF3
	ProtectionSchemeInvalid Reason = 0xE7
	OnlyProtectionSupported Reason = 0xE6
	UnknownSenderID         Reason = 0xE8
	WildcardNotSupported    Reason = 0xA2
	SharedSubsNotSupported  Reason = 0x9E
	RetainNotSupported      Reason = 0x9A
	QoSNotSupported         Reason = 0x9B
	AdministrativeAction    Reason = 0x98
	ReceiveMaximumExceeded  Reason = 0x93
	PacketIDInUse           Reason = 0x91
	NoMatchingSubscribers   Reason = 0x10
	MaximumConnectTime      Reason = 0xA0
	ConnectionRateExceeded  Reason = 0x9F
	UseAnotherServer        Reason = 0x9C
	ServerMoved             Reason = 0x9D
	PayloadFormatInvalid    Reason = 0x99
	TopicAliasInvalid       Reason = 0x94
	PacketRateTooHigh       Reason = 0x96
	SubscriptionIDsNotSupp  Reason = 0xA1
	BannedClient            Reason = 0x8A
	NormalDisconnection     Reason = 0x00
	GrantedQoS0             Reason = 0x00
)

// Failed reports a failure code (clause 2.3).
func (r Reason) Failed() bool { return r >= 0x80 }

// Will is the will carried in CONNECT (clauses 3.1.3, 3.1.10 to 3.1.13).
type Will struct {
	TopicType  byte
	QoS        byte
	Retain     bool
	TopicAlias uint16 // TopicType TopicSession or TopicPredefined
	TopicName  string // TopicType TopicName
	Payload    []byte
}

// Auth is an authentication method and its data (clauses 3.1.14 to 3.1.17).
type Auth struct {
	Method string
	Data   []byte
}

// Packet is any MQTT-SN 2.0 packet. Only the fields of its type are used:
//
//	CONNECT     CleanStart Will Auth HasSessionExpiry/SessionExpiry HasDefaultAwake/DefaultAwake
//	            AllowAddrChange AllowServerValues PacketID Version KeepAlive MaxPacketSize ClientID
//	CONNACK     SessionPresent PacketID Reason HasSessionExpiry/SessionExpiry
//	            HasServerKeepAlive/ServerKeepAlive Auth ClientID (assigned)
//	AUTH        PacketID Reason Auth
//	REGISTER    PacketID HasTopicAlias/TopicAlias TopicName
//	REGACK      TopicType PacketID HasTopicAlias/TopicAlias Reason
//	PUBWOS      TopicType Retain TopicAlias|TopicName Payload
//	PUBLISH     DUP QoS Retain TopicType PacketID (QoS > 0) TopicAlias|TopicName Payload
//	PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK  PacketID Reason
//	SUBSCRIBE   NoLocal QoS RetainAsPublished RetainHandling TopicType PacketID TopicAlias|TopicName
//	SUBACK      TopicType PacketID HasTopicAlias/TopicAlias Reason
//	UNSUBSCRIBE TopicType PacketID TopicAlias|TopicName
//	PINGREQ     PacketID
//	PINGRESP    PacketID HasRemaining/Remaining
//	DISCONNECT  HasPacketID/PacketID HasSessionExpiry/SessionExpiry HasReason/Reason ReasonString
//	SLEEPREQ    RetainAliases PacketID SleepDuration
//	SLEEPRESP   HasSleepDuration/SleepDuration PacketID Reason
//	ADVERTISE   GwID Duration
//	SEARCHGW    Extra
//	GWINFO      GwID GwAdd
//
// An optional trailing Reason is written when HasReason is set or Reason
// is not 0; on decode HasReason tells whether it was present (absent means
// Success).
type Packet struct {
	Type     Type
	PacketID uint16
	// HasPacketID: DISCONNECT only (clause 3.13.2.1).
	HasPacketID bool
	Reason      Reason
	HasReason   bool

	CleanStart        bool
	AllowAddrChange   bool
	AllowServerValues bool
	Version           byte
	KeepAlive         uint16
	MaxPacketSize     uint16
	HasDefaultAwake   bool
	DefaultAwake      byte
	HasSessionExpiry  bool
	SessionExpiry     uint32
	Will              *Will
	Auth              *Auth
	ClientID          string

	SessionPresent     bool
	HasServerKeepAlive bool
	ServerKeepAlive    uint16

	TopicType     byte
	HasTopicAlias bool
	TopicAlias    uint16
	TopicName     string

	DUP     bool
	QoS     byte
	Retain  bool
	Payload []byte

	NoLocal           bool
	RetainAsPublished bool
	RetainHandling    byte

	HasRemaining bool
	Remaining    byte

	ReasonString string

	RetainAliases    bool
	HasSleepDuration bool
	SleepDuration    uint32

	GwID     byte
	Duration uint16
	GwAdd    []byte
	Extra    []byte

	// Reserved is set on decode when a reserved flag bit is 1 or a
	// reserved value is used (QoS 3, topic type 2, Retain Handling 3, DUP
	// on a QoS 0 or 1 PUBLISH): a Malformed Packet or Protocol Error the
	// receiver may still choose to accept.
	Reserved bool
	// BadUTF8 is set on decode when a string field is not valid UTF-8
	// (clause 1.8.4).
	BadUTF8 bool
}

// ErrShort is returned for a datagram too short for its header or fields.
var ErrShort = errors.New("mqtt-sn 2.0: packet too short")

// Header parses the length header of an MQTT-SN datagram (clause 2.1.2,
// the same in 1.2): the total length and the header size, so that b[hdr]
// is the packet type. ok is false if the header is malformed.
func Header(b []byte) (n, hdr int, ok bool) {
	if len(b) < 2 {
		return 0, 0, false
	}
	if b[0] == 0x01 {
		if len(b) < 4 {
			return 0, 0, false
		}
		n, hdr = int(binary.BigEndian.Uint16(b[1:3])), 3
	} else {
		n, hdr = int(b[0]), 1
	}
	if n < hdr+1 {
		return 0, 0, false
	}
	return n, hdr, true
}

type reader struct {
	p   []byte
	i   int
	err error
	t   Type
}

func (r *reader) fail(what string, k int) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: %s needs %d more bytes for %s", ErrShort, r.t, k-(len(r.p)-r.i), what)
	}
}

func (r *reader) u8(what string) byte {
	if r.err != nil || r.i+1 > len(r.p) {
		r.fail(what, 1)
		return 0
	}
	v := r.p[r.i]
	r.i++
	return v
}

func (r *reader) u16(what string) uint16 {
	if r.err != nil || r.i+2 > len(r.p) {
		r.fail(what, 2)
		return 0
	}
	v := binary.BigEndian.Uint16(r.p[r.i:])
	r.i += 2
	return v
}

func (r *reader) u32(what string) uint32 {
	if r.err != nil || r.i+4 > len(r.p) {
		r.fail(what, 4)
		return 0
	}
	v := binary.BigEndian.Uint32(r.p[r.i:])
	r.i += 4
	return v
}

func (r *reader) bytes(what string, k int) []byte {
	if r.err != nil || r.i+k > len(r.p) {
		r.fail(what, k)
		return nil
	}
	v := append([]byte(nil), r.p[r.i:r.i+k]...)
	r.i += k
	return v
}

func (r *reader) rest() []byte {
	if r.err != nil || r.i >= len(r.p) {
		return nil
	}
	v := append([]byte(nil), r.p[r.i:]...)
	r.i = len(r.p)
	return v
}

func (r *reader) more() bool { return r.err == nil && r.i < len(r.p) }

func (m *Packet) str(b []byte) string {
	if !utf8.Valid(b) {
		m.BadUTF8 = true
	}
	return string(b)
}

// Decode parses one datagram. It never panics, whatever the input.
func Decode(b []byte) (*Packet, error) {
	n, hdr, ok := Header(b)
	if !ok {
		return nil, ErrShort
	}
	if n > len(b) {
		return nil, fmt.Errorf("mqtt-sn 2.0: length %d but only %d bytes received", n, len(b))
	}
	m := &Packet{Type: Type(b[hdr])}
	r := &reader{p: b[hdr+1 : n], t: m.Type}
	reserved := func(v, mask byte) {
		if v&mask != 0 {
			m.Reserved = true
		}
	}
	topicType := func(v byte) byte {
		t := v & 0x03
		if t == TopicReserved {
			m.Reserved = true
		}
		return t
	}
	optReason := func() {
		if r.more() {
			m.Reason, m.HasReason = Reason(r.u8("Reason Code")), true
		}
	}
	switch m.Type {
	case CONNECT:
		f := r.u8("Connect Flags")
		reserved(f, 0x80)
		m.CleanStart, m.AllowAddrChange, m.AllowServerValues = f&0x01 != 0, f&0x20 != 0, f&0x40 != 0
		m.HasDefaultAwake, m.HasSessionExpiry = f&0x10 != 0, f&0x08 != 0
		hasWill, hasAuth := f&0x02 != 0, f&0x04 != 0
		var wf byte
		if hasWill {
			wf = r.u8("Will Flags")
			reserved(wf, 0xE0)
		}
		m.PacketID = r.u16("Packet Identifier")
		m.Version = r.u8("Protocol Version")
		m.KeepAlive = r.u16("Keep Alive")
		m.MaxPacketSize = r.u16("Maximum Packet Size")
		if m.HasDefaultAwake {
			m.DefaultAwake = r.u8("Default Awake Messages")
		}
		if m.HasSessionExpiry {
			m.SessionExpiry = r.u32("Session Expiry Interval")
		}
		if hasWill {
			w := &Will{TopicType: topicType(wf), QoS: (wf >> 2) & 0x03, Retain: wf&0x10 != 0}
			if w.QoS == 3 {
				m.Reserved = true
			}
			v := r.u16("Will Topic Alias or Will Topic Name Length")
			if w.TopicType == TopicName {
				w.TopicName = m.str(r.bytes("Will Topic Name", int(v)))
			} else {
				w.TopicAlias = v
			}
			w.Payload = r.bytes("Will Payload", int(r.u16("Will Payload Length")))
			m.Will = w
		}
		if hasAuth {
			a := &Auth{}
			a.Method = m.str(r.bytes("Authentication Method", int(r.u8("Authentication Method Length"))))
			a.Data = r.bytes("Authentication Data", int(r.u16("Authentication Data Length")))
			m.Auth = a
		}
		m.ClientID = m.str(r.rest())
	case CONNACK:
		f := r.u8("CONNACK Flags")
		reserved(f, 0xF0)
		m.SessionPresent, m.HasSessionExpiry, m.HasServerKeepAlive = f&0x01 != 0, f&0x02 != 0, f&0x04 != 0
		m.PacketID = r.u16("Packet Identifier")
		m.Reason, m.HasReason = Reason(r.u8("Reason Code")), true
		if m.HasSessionExpiry {
			m.SessionExpiry = r.u32("Session Expiry Interval")
		}
		if m.HasServerKeepAlive {
			m.ServerKeepAlive = r.u16("Server Keep Alive")
		}
		if f&0x08 != 0 {
			a := &Auth{}
			a.Method = m.str(r.bytes("Authentication Method", int(r.u8("Authentication Method Length"))))
			a.Data = r.bytes("Authentication Data", int(r.u16("Authentication Data Length")))
			m.Auth = a
		}
		m.ClientID = m.str(r.rest())
	case AUTH:
		m.PacketID = r.u16("Packet Identifier")
		m.Reason, m.HasReason = Reason(r.u8("Reason Code")), true
		a := &Auth{}
		a.Method = m.str(r.bytes("Authentication Method", int(r.u8("Authentication Method Length"))))
		a.Data = r.rest()
		m.Auth = a
	case REGISTER:
		f := r.u8("REGISTER Flags")
		reserved(f, 0xFE)
		m.HasTopicAlias = f&0x01 != 0
		m.PacketID = r.u16("Packet Identifier")
		if m.HasTopicAlias {
			m.TopicAlias = r.u16("Topic Alias")
		}
		m.TopicName = m.str(r.rest())
	case REGACK, SUBACK:
		f := r.u8("Flags")
		reserved(f, 0xF8)
		m.TopicType, m.HasTopicAlias = topicType(f), f&0x04 != 0
		m.PacketID = r.u16("Packet Identifier")
		if m.HasTopicAlias {
			m.TopicAlias = r.u16("Topic Alias")
		}
		optReason()
	case PUBWOS:
		f := r.u8("PUBWOS Flags")
		reserved(f, 0xEC)
		m.TopicType, m.Retain = topicType(f), f&0x10 != 0
		m.topicAndPayload(r)
	case PUBLISH:
		f := r.u8("PUBLISH Flags")
		reserved(f, 0x0C)
		m.DUP, m.QoS, m.Retain, m.TopicType = f&0x80 != 0, (f>>5)&0x03, f&0x10 != 0, topicType(f)
		if m.QoS == 3 || m.DUP && m.QoS < 2 {
			m.Reserved = true
		}
		if m.QoS > 0 {
			m.PacketID = r.u16("Packet Identifier")
		}
		m.topicAndPayload(r)
	case PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK:
		m.PacketID = r.u16("Packet Identifier")
		optReason()
	case SUBSCRIBE, UNSUBSCRIBE:
		f := r.u8("Flags")
		if m.Type == SUBSCRIBE {
			m.NoLocal, m.QoS, m.RetainAsPublished, m.RetainHandling = f&0x80 != 0, (f>>5)&0x03, f&0x10 != 0, (f>>2)&0x03
			if m.QoS == 3 || m.RetainHandling == 3 {
				m.Reserved = true
			}
		} else {
			reserved(f, 0xFC)
		}
		m.TopicType = topicType(f)
		m.PacketID = r.u16("Packet Identifier")
		if m.TopicType == TopicName {
			m.TopicName = m.str(r.rest())
		} else {
			m.TopicAlias = r.u16("Topic Alias")
		}
	case PINGREQ:
		m.PacketID = r.u16("Packet Identifier")
	case PINGRESP:
		m.PacketID = r.u16("Packet Identifier")
		if r.more() {
			m.Remaining, m.HasRemaining = r.u8("Application Messages Remaining"), true
		}
	case DISCONNECT:
		// A DISCONNECT without flags (two bytes) is taken as all absent.
		var f byte
		if r.more() {
			f = r.u8("DISCONNECT Flags")
		}
		reserved(f, 0xF8)
		m.HasPacketID, m.HasSessionExpiry, m.HasReason = f&0x01 != 0, f&0x02 != 0, f&0x04 != 0
		if m.HasPacketID {
			m.PacketID = r.u16("Packet Identifier")
		}
		if m.HasSessionExpiry {
			m.SessionExpiry = r.u32("Session Expiry Interval")
		}
		if m.HasReason {
			m.Reason = Reason(r.u8("Reason Code"))
			m.ReasonString = m.str(r.rest())
		}
	case WAKEUP:
	case SLEEPREQ:
		f := r.u8("SLEEPREQ Flags")
		reserved(f, 0xFE)
		m.RetainAliases = f&0x01 != 0
		m.PacketID = r.u16("Packet Identifier")
		m.SleepDuration = r.u32("Sleep Duration")
	case SLEEPRESP:
		f := r.u8("SLEEPRESP Flags")
		reserved(f, 0xFE)
		m.HasSleepDuration = f&0x01 != 0
		m.PacketID = r.u16("Packet Identifier")
		if m.HasSleepDuration {
			m.SleepDuration = r.u32("Sleep Duration")
		}
		optReason()
	case ADVERTISE:
		m.GwID = r.u8("Gateway Identifier")
		m.Duration = r.u16("Duration")
	case SEARCHGW:
		m.Extra = r.rest()
	case GWINFO:
		m.GwID = r.u8("Gateway Identifier")
		m.GwAdd = r.rest()
	default:
		return nil, fmt.Errorf("mqtt-sn 2.0: packet type %s is not supported", m.Type)
	}
	if r.err != nil {
		return nil, r.err
	}
	return m, nil
}

// topicAndPayload reads the Topic Alias or Topic Name Length, the Topic
// Name and the Payload of PUBLISH and PUBWOS (clauses 3.6.1.3 to 3.6.1.5).
func (m *Packet) topicAndPayload(r *reader) {
	v := r.u16("Topic Alias or Topic Name Length")
	if m.TopicType == TopicName {
		m.TopicName = m.str(r.bytes("Topic Name", int(v)))
	} else {
		m.TopicAlias = v
	}
	m.Payload = r.rest()
}

// Encode serialises m, choosing the one- or three-byte length form.
func (m *Packet) Encode() []byte {
	p := make([]byte, 0, 24+len(m.Payload)+len(m.TopicName)+len(m.ClientID)+len(m.ReasonString))
	u16 := func(v uint16) { p = binary.BigEndian.AppendUint16(p, v) }
	u32 := func(v uint32) { p = binary.BigEndian.AppendUint32(p, v) }
	bit := func(b bool, v byte) byte {
		if b {
			return v
		}
		return 0
	}
	auth := func(a *Auth, dataLen bool) {
		p = append(p, byte(len(a.Method)))
		p = append(p, a.Method...)
		if dataLen {
			u16(uint16(len(a.Data)))
		}
		p = append(p, a.Data...)
	}
	optReason := func() {
		if m.HasReason || m.Reason != 0 {
			p = append(p, byte(m.Reason))
		}
	}
	topic := func() {
		if m.TopicType == TopicName {
			u16(uint16(len(m.TopicName)))
			p = append(p, m.TopicName...)
		} else {
			u16(m.TopicAlias)
		}
	}
	switch m.Type {
	case CONNECT:
		f := bit(m.CleanStart, 0x01) | bit(m.Will != nil, 0x02) | bit(m.Auth != nil, 0x04) |
			bit(m.HasSessionExpiry, 0x08) | bit(m.HasDefaultAwake, 0x10) | bit(m.AllowAddrChange, 0x20) |
			bit(m.AllowServerValues, 0x40)
		p = append(p, f)
		if w := m.Will; w != nil {
			p = append(p, w.TopicType&0x03|(w.QoS&0x03)<<2|bit(w.Retain, 0x10))
		}
		u16(m.PacketID)
		p = append(p, m.Version)
		u16(m.KeepAlive)
		u16(m.MaxPacketSize)
		if m.HasDefaultAwake {
			p = append(p, m.DefaultAwake)
		}
		if m.HasSessionExpiry {
			u32(m.SessionExpiry)
		}
		if w := m.Will; w != nil {
			if w.TopicType == TopicName {
				u16(uint16(len(w.TopicName)))
				p = append(p, w.TopicName...)
			} else {
				u16(w.TopicAlias)
			}
			u16(uint16(len(w.Payload)))
			p = append(p, w.Payload...)
		}
		if m.Auth != nil {
			auth(m.Auth, true)
		}
		p = append(p, m.ClientID...)
	case CONNACK:
		p = append(p, bit(m.SessionPresent, 0x01)|bit(m.HasSessionExpiry, 0x02)|bit(m.HasServerKeepAlive, 0x04)|bit(m.Auth != nil, 0x08))
		u16(m.PacketID)
		p = append(p, byte(m.Reason))
		if m.HasSessionExpiry {
			u32(m.SessionExpiry)
		}
		if m.HasServerKeepAlive {
			u16(m.ServerKeepAlive)
		}
		if m.Auth != nil {
			auth(m.Auth, true)
		}
		p = append(p, m.ClientID...)
	case AUTH:
		u16(m.PacketID)
		p = append(p, byte(m.Reason))
		a := m.Auth
		if a == nil {
			a = &Auth{}
		}
		auth(a, false)
	case REGISTER:
		p = append(p, bit(m.HasTopicAlias, 0x01))
		u16(m.PacketID)
		if m.HasTopicAlias {
			u16(m.TopicAlias)
		}
		p = append(p, m.TopicName...)
	case REGACK, SUBACK:
		p = append(p, m.TopicType&0x03|bit(m.HasTopicAlias, 0x04))
		u16(m.PacketID)
		if m.HasTopicAlias {
			u16(m.TopicAlias)
		}
		optReason()
	case PUBWOS:
		p = append(p, m.TopicType&0x03|bit(m.Retain, 0x10))
		topic()
		p = append(p, m.Payload...)
	case PUBLISH:
		p = append(p, m.TopicType&0x03|bit(m.Retain, 0x10)|(m.QoS&0x03)<<5|bit(m.DUP && m.QoS == 2, 0x80))
		if m.QoS > 0 {
			u16(m.PacketID)
		}
		topic()
		p = append(p, m.Payload...)
	case PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK:
		u16(m.PacketID)
		optReason()
	case SUBSCRIBE, UNSUBSCRIBE:
		f := m.TopicType & 0x03
		if m.Type == SUBSCRIBE {
			f |= bit(m.NoLocal, 0x80) | (m.QoS&0x03)<<5 | bit(m.RetainAsPublished, 0x10) | (m.RetainHandling&0x03)<<2
		}
		p = append(p, f)
		u16(m.PacketID)
		if m.TopicType == TopicName {
			p = append(p, m.TopicName...)
		} else {
			u16(m.TopicAlias)
		}
	case PINGREQ:
		u16(m.PacketID)
	case PINGRESP:
		u16(m.PacketID)
		if m.HasRemaining {
			p = append(p, m.Remaining)
		}
	case DISCONNECT:
		hasReason := m.HasReason || m.Reason != 0 || m.ReasonString != ""
		p = append(p, bit(m.HasPacketID, 0x01)|bit(m.HasSessionExpiry, 0x02)|bit(hasReason, 0x04))
		if m.HasPacketID {
			u16(m.PacketID)
		}
		if m.HasSessionExpiry {
			u32(m.SessionExpiry)
		}
		if hasReason {
			p = append(p, byte(m.Reason))
			p = append(p, m.ReasonString...)
		}
	case WAKEUP:
	case SLEEPREQ:
		p = append(p, bit(m.RetainAliases, 0x01))
		u16(m.PacketID)
		u32(m.SleepDuration)
	case SLEEPRESP:
		p = append(p, bit(m.HasSleepDuration, 0x01))
		u16(m.PacketID)
		if m.HasSleepDuration {
			u32(m.SleepDuration)
		}
		optReason()
	case ADVERTISE:
		p = append(p, m.GwID)
		u16(m.Duration)
	case SEARCHGW:
		p = append(p, m.Extra...)
	case GWINFO:
		p = append(p, m.GwID)
		p = append(p, m.GwAdd...)
	}
	return frame(byte(m.Type), p)
}

// frame prefixes a packet body with its length header and type.
func frame(typ byte, p []byte) []byte {
	if n := len(p) + 2; n < 256 {
		return append([]byte{byte(n), typ}, p...)
	}
	n := len(p) + 4
	return append([]byte{0x01, byte(n >> 8), byte(n), typ}, p...)
}

// Envelope builds the header of an envelope (0xFD, 0xFE) around info; the
// wrapped packet is appended after it (clauses 3.18.1 and 3.19.1).
func Envelope(typ Type, info []byte) []byte { return frame(byte(typ), info) }

// Unwrap splits an envelope of type typ into its header information and
// the wrapped packet; ok is false for any other datagram.
func Unwrap(b []byte, typ Type) (info, inner []byte, ok bool) {
	n, hdr, ok := Header(b)
	if !ok || Type(b[hdr]) != typ || n > len(b) || n == len(b) {
		return nil, nil, false
	}
	return b[hdr+1 : n], b[n:], true
}

// BasicCredentials parses the Authentication Data of method MQTT-BASIC:
// a length-prefixed user name and a length-prefixed password (clause
// 4.11.1.2).
func BasicCredentials(data []byte) (user string, password []byte, ok bool) {
	r := &reader{p: data, t: AUTH}
	user = string(r.bytes("User Name", int(r.u16("User Name Length"))))
	password = r.bytes("Password", int(r.u16("Password Length")))
	return user, password, r.err == nil && utf8.ValidString(user)
}

// BasicData builds MQTT-BASIC Authentication Data.
func BasicData(user string, password []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(user)))
	b = append(b, user...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(password)))
	return append(b, password...)
}

// Auth methods of clause 4.11.1.2.
const (
	MethodBasic    = "MQTT-BASIC"
	MethodEnhanced = "MQTT-ENHANCED"
)
