package mqttsn_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/cB-Sigma/mqttsn"
)

// MQTT-SN 1.2 clause 5.2.1: the Length field is one octet, or 0x01
// followed by a two-octet big-endian total length. The long form may be
// used for any length; the encoder switches to it at 256 octets.
//
// Covers: SIG-IPE-3440
func TestMQTTSNLengthForms(t *testing.T) {
	// The three-octet form for short messages decodes like the one-octet form.
	for _, c := range []struct {
		in   []byte
		want *mqttsn.Message
	}{
		{[]byte{0x01, 0x00, 0x04, 0x16}, &mqttsn.Message{Type: mqttsn.PINGREQ}},
		{[]byte{0x01, 0x00, 0x05, 0x05, 0x02}, &mqttsn.Message{Type: mqttsn.CONNACK, ReturnCode: mqttsn.RejectedTopicID}},
		{[]byte{0x01, 0x00, 0x06, 0x18, 0x00, 0x3C}, &mqttsn.Message{Type: mqttsn.DISCONNECT, HasDuration: true, Duration: 60}},
	} {
		got, err := mqttsn.Decode(c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("Decode(% x) = %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
	// PUBLISH has 7 octets besides its data in the one-octet form.
	at := func(n int) []byte {
		return (&mqttsn.Message{Type: mqttsn.PUBLISH, TopicID: 1, Data: bytes.Repeat([]byte{'x'}, n)}).Encode()
	}
	if b := at(248); len(b) != 255 || b[0] != 255 || b[1] != byte(mqttsn.PUBLISH) {
		t.Errorf("255-octet message header % x, length %d", b[:2], len(b))
	}
	if b := at(249); len(b) != 258 || b[0] != 0x01 || b[1] != 0x01 || b[2] != 0x02 || b[3] != byte(mqttsn.PUBLISH) {
		t.Errorf("258-octet message header % x, length %d", b[:4], len(b))
	}
	big := at(65535 - 9)
	if len(big) != 65535 || big[0] != 0x01 || big[1] != 0xFF || big[2] != 0xFF {
		t.Errorf("largest message header % x, length %d", big[:4], len(big))
	}
	if m, err := mqttsn.Decode(big); err != nil || len(m.Data) != 65535-9 {
		t.Errorf("largest message decode: %v", err)
	}
	if mqttsn.MaxLength != 65535 {
		t.Errorf("MaxLength = %d", mqttsn.MaxLength)
	}
	// A length smaller than its own header, or larger than the datagram, is refused.
	for _, in := range [][]byte{{0x00, 0x16}, {0x01, 0x00, 0x03, 0x16}, {0x01, 0x00, 0x01, 0x16}, {0x05, 0x16}, {0x01, 0x00, 0x09, 0x16}} {
		if _, err := mqttsn.Decode(in); err == nil {
			t.Errorf("Decode(% x) accepted", in)
		}
	}
}

// MQTT-SN 1.2 clause 5.2.2 Table 3: message type codes; reserved codes
// are not decoded (0xFE is only read as an encapsulation, clause 5.5).
//
// Covers: SIG-IPE-3441
func TestMQTTSNMessageTypeCodes(t *testing.T) {
	want := map[mqttsn.MsgType]byte{
		mqttsn.ADVERTISE: 0x00, mqttsn.SEARCHGW: 0x01, mqttsn.GWINFO: 0x02, mqttsn.CONNECT: 0x04,
		mqttsn.CONNACK: 0x05, mqttsn.WILLTOPICREQ: 0x06, mqttsn.WILLTOPIC: 0x07, mqttsn.WILLMSGREQ: 0x08,
		mqttsn.WILLMSG: 0x09, mqttsn.REGISTER: 0x0A, mqttsn.REGACK: 0x0B, mqttsn.PUBLISH: 0x0C,
		mqttsn.PUBACK: 0x0D, mqttsn.PUBCOMP: 0x0E, mqttsn.PUBREC: 0x0F, mqttsn.PUBREL: 0x10,
		mqttsn.SUBSCRIBE: 0x12, mqttsn.SUBACK: 0x13, mqttsn.UNSUBSCRIBE: 0x14, mqttsn.UNSUBACK: 0x15,
		mqttsn.PINGREQ: 0x16, mqttsn.PINGRESP: 0x17, mqttsn.DISCONNECT: 0x18, mqttsn.WILLTOPICUPD: 0x1A,
		mqttsn.WILLTOPICRESP: 0x1B, mqttsn.WILLMSGUPD: 0x1C, mqttsn.WILLMSGRESP: 0x1D, mqttsn.Encapsulated: 0xFE,
	}
	for typ, code := range want {
		if byte(typ) != code {
			t.Errorf("%s = %#x, want %#x", typ, byte(typ), code)
		}
	}
	for _, code := range []byte{0x03, 0x11, 0x19, 0x1E, 0x80, 0xFD, 0xFE, 0xFF} {
		if _, err := mqttsn.Decode([]byte{0x04, code, 0x00, 0x00}); err == nil {
			t.Errorf("reserved type %#x decoded", code)
		}
	}
}

// MQTT-SN 1.2 clause 5.3.4 Table 4: DUP bit 7, QoS bits 6-5 (0b11 is
// QoS -1), Retain bit 4, Will bit 3, CleanSession bit 2, TopicIdType bits
// 1-0 (0b00 normal, 0b01 predefined, 0b10 short, 0b11 reserved).
//
// Covers: SIG-IPE-3442
func TestMQTTSNFlagBits(t *testing.T) {
	for _, c := range []struct {
		f mqttsn.Flags
		b byte
	}{
		{mqttsn.Flags{DUP: true}, 0x80},
		{mqttsn.Flags{QoS: 1}, 0x20},
		{mqttsn.Flags{QoS: 2}, 0x40},
		{mqttsn.Flags{QoS: -1}, 0x60},
		{mqttsn.Flags{Retain: true}, 0x10},
		{mqttsn.Flags{Will: true}, 0x08},
		{mqttsn.Flags{CleanSession: true}, 0x04},
		{mqttsn.Flags{TopicIDType: mqttsn.TopicPredefined}, 0x01},
		{mqttsn.Flags{TopicIDType: mqttsn.TopicShort}, 0x02},
		{mqttsn.Flags{TopicIDType: mqttsn.TopicReserved}, 0x03},
		{mqttsn.Flags{}, 0x00},
		{mqttsn.Flags{DUP: true, QoS: -1, Retain: true, Will: true, CleanSession: true, TopicIDType: mqttsn.TopicShort}, 0xFE},
	} {
		if got := c.f.Byte(); got != c.b {
			t.Errorf("%+v.Byte() = %#x, want %#x", c.f, got, c.b)
		}
		if got := mqttsn.ParseFlags(c.b); got != c.f {
			t.Errorf("ParseFlags(%#x) = %+v, want %+v", c.b, got, c.f)
		}
	}
	if mqttsn.TopicNormal != 0 || mqttsn.TopicPredefined != 1 || mqttsn.TopicShort != 2 || mqttsn.TopicReserved != 3 {
		t.Error("topic ID type constants")
	}
}

// MQTT-SN 1.2 clause 5.3.8 (ProtocolId 0x01) and 5.3.10 Table 5 (return
// codes 0x00 to 0x03).
//
// Covers: SIG-IPE-3443
func TestMQTTSNProtocolIDAndReturnCodes(t *testing.T) {
	if mqttsn.ProtocolID != 0x01 {
		t.Errorf("ProtocolID = %#x", mqttsn.ProtocolID)
	}
	for rc, want := range map[mqttsn.ReturnCode]byte{mqttsn.Accepted: 0, mqttsn.RejectedCongested: 1, mqttsn.RejectedTopicID: 2, mqttsn.RejectedNotSupp: 3} {
		if byte(rc) != want {
			t.Errorf("return code %d, want %d", rc, want)
		}
	}
	// A reserved return code survives decoding unchanged.
	if m, err := mqttsn.Decode([]byte{0x03, 0x05, 0x7F}); err != nil || m.ReturnCode != 0x7F {
		t.Errorf("CONNACK 0x7F = %+v, %v", m, err)
	}
}

// MQTT-SN 1.2 clause 5.4 (Tables 6 to 27): the octet layout of every
// message, both ways.
//
// Covers: SIG-IPE-3444
func TestMQTTSNMessageLayouts(t *testing.T) {
	for _, c := range []struct {
		clause string
		m      *mqttsn.Message
		b      []byte
	}{
		{"5.4.1", &mqttsn.Message{Type: mqttsn.ADVERTISE, GwID: 7, Duration: 900}, []byte{0x05, 0x00, 0x07, 0x03, 0x84}},
		{"5.4.2", &mqttsn.Message{Type: mqttsn.SEARCHGW, Radius: 1}, []byte{0x03, 0x01, 0x01}},
		{"5.4.3", &mqttsn.Message{Type: mqttsn.GWINFO, GwID: 3}, []byte{0x03, 0x02, 0x03}},
		{"5.4.3 GwAdd", &mqttsn.Message{Type: mqttsn.GWINFO, GwID: 3, GwAdd: []byte{0xC0, 0xA8, 1, 2}}, []byte{0x07, 0x02, 0x03, 0xC0, 0xA8, 0x01, 0x02}},
		{"5.4.4", &mqttsn.Message{Type: mqttsn.CONNECT, Flags: mqttsn.Flags{CleanSession: true}, ProtocolID: 1, Duration: 30, ClientID: "ab"}, []byte{0x08, 0x04, 0x04, 0x01, 0x00, 0x1E, 'a', 'b'}},
		{"5.4.5", &mqttsn.Message{Type: mqttsn.CONNACK, ReturnCode: mqttsn.RejectedCongested}, []byte{0x03, 0x05, 0x01}},
		{"5.4.6", &mqttsn.Message{Type: mqttsn.WILLTOPICREQ}, []byte{0x02, 0x06}},
		{"5.4.7", &mqttsn.Message{Type: mqttsn.WILLTOPIC, Flags: mqttsn.Flags{QoS: 1, Retain: true}, TopicName: "t"}, []byte{0x04, 0x07, 0x30, 't'}},
		{"5.4.8", &mqttsn.Message{Type: mqttsn.WILLMSGREQ}, []byte{0x02, 0x08}},
		{"5.4.9", &mqttsn.Message{Type: mqttsn.WILLMSG, Data: []byte("x")}, []byte{0x03, 0x09, 'x'}},
		{"5.4.10", &mqttsn.Message{Type: mqttsn.REGISTER, MsgID: 5, TopicName: "a"}, []byte{0x07, 0x0A, 0x00, 0x00, 0x00, 0x05, 'a'}},
		{"5.4.11", &mqttsn.Message{Type: mqttsn.REGACK, TopicID: 9, MsgID: 5}, []byte{0x07, 0x0B, 0x00, 0x09, 0x00, 0x05, 0x00}},
		{"5.4.12", &mqttsn.Message{Type: mqttsn.PUBLISH, Flags: mqttsn.Flags{QoS: 1}, TopicID: 0x1234, MsgID: 0xBEEF, Data: []byte{1}}, []byte{0x08, 0x0C, 0x20, 0x12, 0x34, 0xBE, 0xEF, 0x01}},
		{"5.4.12 QoS -1 short", &mqttsn.Message{Type: mqttsn.PUBLISH, Flags: mqttsn.Flags{QoS: -1, TopicIDType: mqttsn.TopicShort}, TopicID: 0x6162, Data: []byte{9}}, []byte{0x08, 0x0C, 0x62, 0x61, 0x62, 0x00, 0x00, 0x09}},
		{"5.4.13", &mqttsn.Message{Type: mqttsn.PUBACK, TopicID: 1, MsgID: 2, ReturnCode: mqttsn.RejectedTopicID}, []byte{0x07, 0x0D, 0x00, 0x01, 0x00, 0x02, 0x02}},
		{"5.4.14 PUBCOMP", &mqttsn.Message{Type: mqttsn.PUBCOMP, MsgID: 12}, []byte{0x04, 0x0E, 0x00, 0x0C}},
		{"5.4.14 PUBREC", &mqttsn.Message{Type: mqttsn.PUBREC, MsgID: 10}, []byte{0x04, 0x0F, 0x00, 0x0A}},
		{"5.4.14 PUBREL", &mqttsn.Message{Type: mqttsn.PUBREL, MsgID: 11}, []byte{0x04, 0x10, 0x00, 0x0B}},
		{"5.4.15 name", &mqttsn.Message{Type: mqttsn.SUBSCRIBE, Flags: mqttsn.Flags{QoS: 1}, MsgID: 3, TopicName: "a/#"}, []byte{0x08, 0x12, 0x20, 0x00, 0x03, 'a', '/', '#'}},
		{"5.4.15 predefined", &mqttsn.Message{Type: mqttsn.SUBSCRIBE, Flags: mqttsn.Flags{QoS: 2, TopicIDType: mqttsn.TopicPredefined}, MsgID: 4, TopicID: 17}, []byte{0x07, 0x12, 0x41, 0x00, 0x04, 0x00, 0x11}},
		{"5.4.15 short", &mqttsn.Message{Type: mqttsn.SUBSCRIBE, Flags: mqttsn.Flags{TopicIDType: mqttsn.TopicShort}, MsgID: 5, TopicID: 0x6162}, []byte{0x07, 0x12, 0x02, 0x00, 0x05, 'a', 'b'}},
		{"5.4.16", &mqttsn.Message{Type: mqttsn.SUBACK, Flags: mqttsn.Flags{QoS: 1}, TopicID: 4, MsgID: 3}, []byte{0x08, 0x13, 0x20, 0x00, 0x04, 0x00, 0x03, 0x00}},
		{"5.4.17", &mqttsn.Message{Type: mqttsn.UNSUBSCRIBE, MsgID: 6, TopicName: "x"}, []byte{0x06, 0x14, 0x00, 0x00, 0x06, 'x'}},
		{"5.4.17 predefined", &mqttsn.Message{Type: mqttsn.UNSUBSCRIBE, Flags: mqttsn.Flags{TopicIDType: mqttsn.TopicPredefined}, MsgID: 7, TopicID: 2}, []byte{0x07, 0x14, 0x01, 0x00, 0x07, 0x00, 0x02}},
		{"5.4.18", &mqttsn.Message{Type: mqttsn.UNSUBACK, MsgID: 6}, []byte{0x04, 0x15, 0x00, 0x06}},
		{"5.4.19", &mqttsn.Message{Type: mqttsn.PINGREQ}, []byte{0x02, 0x16}},
		{"5.4.19 ClientId", &mqttsn.Message{Type: mqttsn.PINGREQ, ClientID: "s"}, []byte{0x03, 0x16, 's'}},
		{"5.4.20", &mqttsn.Message{Type: mqttsn.PINGRESP}, []byte{0x02, 0x17}},
		{"5.4.21", &mqttsn.Message{Type: mqttsn.DISCONNECT}, []byte{0x02, 0x18}},
		{"5.4.21 Duration", &mqttsn.Message{Type: mqttsn.DISCONNECT, HasDuration: true, Duration: 300}, []byte{0x04, 0x18, 0x01, 0x2C}},
		{"5.4.22", &mqttsn.Message{Type: mqttsn.WILLTOPICUPD, Flags: mqttsn.Flags{QoS: 2}, TopicName: "t"}, []byte{0x04, 0x1A, 0x40, 't'}},
		{"5.4.23", &mqttsn.Message{Type: mqttsn.WILLMSGUPD, Data: []byte("b")}, []byte{0x03, 0x1C, 'b'}},
		{"5.4.24", &mqttsn.Message{Type: mqttsn.WILLTOPICRESP}, []byte{0x03, 0x1B, 0x00}},
		{"5.4.25", &mqttsn.Message{Type: mqttsn.WILLMSGRESP, ReturnCode: mqttsn.RejectedNotSupp}, []byte{0x03, 0x1D, 0x03}},
	} {
		if got := c.m.Encode(); !bytes.Equal(got, c.b) {
			t.Errorf("%s encode = % x, want % x", c.clause, got, c.b)
		}
		if got, err := mqttsn.Decode(c.b); err != nil || !reflect.DeepEqual(got, c.m) {
			t.Errorf("%s decode = %+v, %v; want %+v", c.clause, got, err, c.m)
		}
	}
}

// MQTT-SN 1.2 clauses 5.4.7 and 5.4.22: an empty WILLTOPIC or WILLTOPICUPD
// has neither Flags nor WillTopic and is exactly two octets.
//
// Covers: SIG-IPE-3445
func TestMQTTSNEmptyWillTopic(t *testing.T) {
	for _, typ := range []mqttsn.MsgType{mqttsn.WILLTOPIC, mqttsn.WILLTOPICUPD} {
		b := (&mqttsn.Message{Type: typ}).Encode()
		if !bytes.Equal(b, []byte{0x02, byte(typ)}) {
			t.Errorf("empty %s = % x", typ, b)
		}
		m, err := mqttsn.Decode(b)
		if err != nil || m.TopicName != "" || m.Flags != (mqttsn.Flags{}) {
			t.Errorf("empty %s decode = %+v, %v", typ, m, err)
		}
	}
}
