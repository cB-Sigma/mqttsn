package mqttsn

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MsgType is an MQTT-SN v1.2 message type (clause 5.2.2).
type MsgType byte

// Message types.
const (
	ADVERTISE     MsgType = 0x00
	SEARCHGW      MsgType = 0x01
	GWINFO        MsgType = 0x02
	CONNECT       MsgType = 0x04
	CONNACK       MsgType = 0x05
	WILLTOPICREQ  MsgType = 0x06
	WILLTOPIC     MsgType = 0x07
	WILLMSGREQ    MsgType = 0x08
	WILLMSG       MsgType = 0x09
	REGISTER      MsgType = 0x0A
	REGACK        MsgType = 0x0B
	PUBLISH       MsgType = 0x0C
	PUBACK        MsgType = 0x0D
	PUBCOMP       MsgType = 0x0E
	PUBREC        MsgType = 0x0F
	PUBREL        MsgType = 0x10
	SUBSCRIBE     MsgType = 0x12
	SUBACK        MsgType = 0x13
	UNSUBSCRIBE   MsgType = 0x14
	UNSUBACK      MsgType = 0x15
	PINGREQ       MsgType = 0x16
	PINGRESP      MsgType = 0x17
	DISCONNECT    MsgType = 0x18
	WILLTOPICUPD  MsgType = 0x1A
	WILLTOPICRESP MsgType = 0x1B
	WILLMSGUPD    MsgType = 0x1C
	WILLMSGRESP   MsgType = 0x1D
)

// Encapsulated is the Encapsulated Message type of a forwarder (clause
// 5.5). Decode does not read it; a gateway unwraps it first.
const Encapsulated MsgType = 0xFE

var typeNames = map[MsgType]string{
	ADVERTISE: "ADVERTISE", SEARCHGW: "SEARCHGW", GWINFO: "GWINFO", CONNECT: "CONNECT", CONNACK: "CONNACK",
	WILLTOPICREQ: "WILLTOPICREQ", WILLTOPIC: "WILLTOPIC", WILLMSGREQ: "WILLMSGREQ", WILLMSG: "WILLMSG",
	REGISTER: "REGISTER", REGACK: "REGACK", PUBLISH: "PUBLISH", PUBACK: "PUBACK", PUBCOMP: "PUBCOMP",
	PUBREC: "PUBREC", PUBREL: "PUBREL", SUBSCRIBE: "SUBSCRIBE", SUBACK: "SUBACK", UNSUBSCRIBE: "UNSUBSCRIBE",
	UNSUBACK: "UNSUBACK", PINGREQ: "PINGREQ", PINGRESP: "PINGRESP", DISCONNECT: "DISCONNECT",
	WILLTOPICUPD: "WILLTOPICUPD", WILLTOPICRESP: "WILLTOPICRESP", WILLMSGUPD: "WILLMSGUPD", WILLMSGRESP: "WILLMSGRESP",
}

func (t MsgType) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("0x%02X", byte(t))
}

// ReturnCode is the result carried by CONNACK, REGACK, PUBACK, SUBACK and
// the will update responses (clause 5.3.10).
type ReturnCode byte

// Return codes.
const (
	Accepted          ReturnCode = 0x00
	RejectedCongested ReturnCode = 0x01
	RejectedTopicID   ReturnCode = 0x02
	RejectedNotSupp   ReturnCode = 0x03
)

// Topic ID types (flags bits 1-0).
const (
	TopicNormal     byte = 0 // a registered topic ID, or a topic name in SUBSCRIBE/UNSUBSCRIBE
	TopicPredefined byte = 1
	TopicShort      byte = 2 // a two-character topic name carried in the topic ID field
	TopicReserved   byte = 3 // reserved (clause 5.3.4)
)

// MaxLength is the largest message the three-octet Length field can
// describe (clause 5.2.1).
const MaxLength = 65535

// ProtocolID is the only protocol identifier of MQTT-SN v1.2 CONNECT.
const ProtocolID = 0x01

// Flags is the flags byte (clause 5.3.4). QoS is 0, 1, 2 or -1 (bits 0b11).
type Flags struct {
	DUP          bool
	QoS          int8
	Retain       bool
	Will         bool
	CleanSession bool
	TopicIDType  byte
}

// Byte encodes the flags.
func (f Flags) Byte() byte {
	var b byte
	if f.DUP {
		b |= 0x80
	}
	switch f.QoS {
	case 1:
		b |= 0x20
	case 2:
		b |= 0x40
	case -1:
		b |= 0x60
	}
	if f.Retain {
		b |= 0x10
	}
	if f.Will {
		b |= 0x08
	}
	if f.CleanSession {
		b |= 0x04
	}
	return b | f.TopicIDType&0x03
}

// ParseFlags decodes a flags byte.
func ParseFlags(b byte) Flags {
	q := int8(b>>5) & 0x03
	if q == 3 {
		q = -1
	}
	return Flags{
		DUP: b&0x80 != 0, QoS: q, Retain: b&0x10 != 0, Will: b&0x08 != 0,
		CleanSession: b&0x04 != 0, TopicIDType: b & 0x03,
	}
}

// Message is any MQTT-SN message. Only the fields of its type are used:
//
//	ADVERTISE     GwID Duration
//	SEARCHGW      Radius
//	GWINFO        GwID GwAdd
//	CONNECT       Flags Duration ClientID (ProtocolID is always 1 on encode)
//	CONNACK, WILLTOPICRESP, WILLMSGRESP  ReturnCode
//	WILLTOPIC, WILLTOPICUPD  Flags TopicName (both empty: no will)
//	WILLMSG, WILLMSGUPD      Data
//	REGISTER      TopicID MsgID TopicName
//	REGACK        TopicID MsgID ReturnCode
//	PUBLISH       Flags TopicID MsgID Data
//	PUBACK        TopicID MsgID ReturnCode
//	PUBREC, PUBREL, PUBCOMP, UNSUBACK  MsgID
//	SUBSCRIBE, UNSUBSCRIBE  Flags MsgID and TopicName (type normal) or TopicID
//	SUBACK        Flags TopicID MsgID ReturnCode
//	PINGREQ       ClientID (optional)
//	DISCONNECT    Duration when HasDuration
type Message struct {
	Type        MsgType
	Flags       Flags
	GwID        byte
	GwAdd       []byte
	Radius      byte
	Duration    uint16
	HasDuration bool
	ProtocolID  byte
	ClientID    string
	ReturnCode  ReturnCode
	TopicID     uint16
	MsgID       uint16
	TopicName   string
	Data        []byte
}

// ErrShort is returned for a datagram too short for its header or type.
var ErrShort = errors.New("mqtt-sn: message too short")

// Decode parses one datagram. It never panics, whatever the input.
func Decode(b []byte) (*Message, error) {
	if len(b) < 2 {
		return nil, ErrShort
	}
	var n, hdr int
	if b[0] == 0x01 {
		if len(b) < 4 {
			return nil, ErrShort
		}
		n, hdr = int(binary.BigEndian.Uint16(b[1:3])), 3
	} else {
		n, hdr = int(b[0]), 1
	}
	if n < hdr+1 {
		return nil, fmt.Errorf("mqtt-sn: length %d is smaller than the header", n)
	}
	if n > len(b) {
		return nil, fmt.Errorf("mqtt-sn: length %d but only %d bytes received", n, len(b))
	}
	b = b[:n]
	m := &Message{Type: MsgType(b[hdr])}
	p := b[hdr+1:]
	need := func(k int) error {
		if len(p) < k {
			return fmt.Errorf("%w: %s needs %d bytes after the type, got %d", ErrShort, m.Type, k, len(p))
		}
		return nil
	}
	u16 := func(i int) uint16 { return binary.BigEndian.Uint16(p[i:]) }
	switch m.Type {
	case ADVERTISE:
		if err := need(3); err != nil {
			return nil, err
		}
		m.GwID, m.Duration = p[0], u16(1)
	case SEARCHGW:
		if err := need(1); err != nil {
			return nil, err
		}
		m.Radius = p[0]
	case GWINFO:
		if err := need(1); err != nil {
			return nil, err
		}
		m.GwID = p[0]
		if len(p) > 1 {
			m.GwAdd = append([]byte(nil), p[1:]...)
		}
	case CONNECT:
		if err := need(4); err != nil {
			return nil, err
		}
		m.Flags, m.ProtocolID, m.Duration, m.ClientID = ParseFlags(p[0]), p[1], u16(2), string(p[4:])
	case CONNACK, WILLTOPICRESP, WILLMSGRESP:
		if err := need(1); err != nil {
			return nil, err
		}
		m.ReturnCode = ReturnCode(p[0])
	case WILLTOPICREQ, WILLMSGREQ, PINGRESP:
	case WILLTOPIC, WILLTOPICUPD:
		if len(p) > 0 {
			m.Flags, m.TopicName = ParseFlags(p[0]), string(p[1:])
		}
	case WILLMSG, WILLMSGUPD:
		if len(p) > 0 {
			m.Data = append([]byte(nil), p...)
		}
	case REGISTER:
		if err := need(4); err != nil {
			return nil, err
		}
		m.TopicID, m.MsgID, m.TopicName = u16(0), u16(2), string(p[4:])
	case REGACK, PUBACK:
		if err := need(5); err != nil {
			return nil, err
		}
		m.TopicID, m.MsgID, m.ReturnCode = u16(0), u16(2), ReturnCode(p[4])
	case PUBLISH:
		if err := need(5); err != nil {
			return nil, err
		}
		m.Flags, m.TopicID, m.MsgID = ParseFlags(p[0]), u16(1), u16(3)
		if len(p) > 5 {
			m.Data = append([]byte(nil), p[5:]...)
		}
	case PUBREC, PUBREL, PUBCOMP, UNSUBACK:
		if err := need(2); err != nil {
			return nil, err
		}
		m.MsgID = u16(0)
	case SUBSCRIBE, UNSUBSCRIBE:
		if err := need(3); err != nil {
			return nil, err
		}
		m.Flags, m.MsgID = ParseFlags(p[0]), u16(1)
		if m.Flags.TopicIDType == TopicNormal {
			m.TopicName = string(p[3:])
		} else {
			if err := need(5); err != nil {
				return nil, err
			}
			m.TopicID = u16(3)
		}
	case SUBACK:
		if err := need(6); err != nil {
			return nil, err
		}
		m.Flags, m.TopicID, m.MsgID, m.ReturnCode = ParseFlags(p[0]), u16(1), u16(3), ReturnCode(p[5])
	case PINGREQ:
		m.ClientID = string(p)
	case DISCONNECT:
		if len(p) >= 2 {
			m.Duration, m.HasDuration = u16(0), true
		}
	default:
		return nil, fmt.Errorf("mqtt-sn: message type %s is not supported", m.Type)
	}
	return m, nil
}

// Encode serialises m, choosing the one- or three-byte length form.
func (m *Message) Encode() []byte {
	p := make([]byte, 0, 16+len(m.Data)+len(m.TopicName)+len(m.ClientID)+len(m.GwAdd))
	u16 := func(v uint16) { p = binary.BigEndian.AppendUint16(p, v) }
	switch m.Type {
	case ADVERTISE:
		p = append(p, m.GwID)
		u16(m.Duration)
	case SEARCHGW:
		p = append(p, m.Radius)
	case GWINFO:
		p = append(p, m.GwID)
		p = append(p, m.GwAdd...)
	case CONNECT:
		p = append(p, m.Flags.Byte(), ProtocolID)
		u16(m.Duration)
		p = append(p, m.ClientID...)
	case CONNACK, WILLTOPICRESP, WILLMSGRESP:
		p = append(p, byte(m.ReturnCode))
	case WILLTOPIC, WILLTOPICUPD:
		if m.TopicName != "" || m.Flags != (Flags{}) {
			p = append(p, m.Flags.Byte())
			p = append(p, m.TopicName...)
		}
	case WILLMSG, WILLMSGUPD:
		p = append(p, m.Data...)
	case REGISTER:
		u16(m.TopicID)
		u16(m.MsgID)
		p = append(p, m.TopicName...)
	case REGACK, PUBACK:
		u16(m.TopicID)
		u16(m.MsgID)
		p = append(p, byte(m.ReturnCode))
	case PUBLISH:
		p = append(p, m.Flags.Byte())
		u16(m.TopicID)
		u16(m.MsgID)
		p = append(p, m.Data...)
	case PUBREC, PUBREL, PUBCOMP, UNSUBACK:
		u16(m.MsgID)
	case SUBSCRIBE, UNSUBSCRIBE:
		p = append(p, m.Flags.Byte())
		u16(m.MsgID)
		if m.Flags.TopicIDType == TopicNormal {
			p = append(p, m.TopicName...)
		} else {
			u16(m.TopicID)
		}
	case SUBACK:
		p = append(p, m.Flags.Byte())
		u16(m.TopicID)
		u16(m.MsgID)
		p = append(p, byte(m.ReturnCode))
	case PINGREQ:
		p = append(p, m.ClientID...)
	case DISCONNECT:
		if m.HasDuration {
			u16(m.Duration)
		}
	}
	n := len(p) + 2
	if n < 256 {
		return append([]byte{byte(n), byte(m.Type)}, p...)
	}
	n = len(p) + 4
	out := []byte{0x01, byte(n >> 8), byte(n), byte(m.Type)}
	return append(out, p...)
}

// ShortTopic packs a two-character topic name into a topic ID field.
func ShortTopic(name string) (uint16, bool) {
	if len(name) != 2 {
		return 0, false
	}
	return uint16(name[0])<<8 | uint16(name[1]), true
}

// ShortName unpacks a short topic name from a topic ID field.
func ShortName(id uint16) string { return string([]byte{byte(id >> 8), byte(id)}) }
