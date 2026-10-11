package mqttsn_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/cB-Sigma/mqttsn"
)

func codecSamples() []*mqttsn.Message {
	f := mqttsn.Flags{DUP: true, QoS: 2, Retain: true, TopicIDType: mqttsn.TopicPredefined}
	return []*mqttsn.Message{
		{Type: mqttsn.ADVERTISE, GwID: 7, Duration: 900},
		{Type: mqttsn.SEARCHGW, Radius: 1},
		{Type: mqttsn.GWINFO, GwID: 3},
		{Type: mqttsn.GWINFO, GwID: 3, GwAdd: []byte{192, 168, 1, 2}},
		{Type: mqttsn.CONNECT, Flags: mqttsn.Flags{Will: true, CleanSession: true}, ProtocolID: 1, Duration: 60, ClientID: "sensor-1"},
		{Type: mqttsn.CONNACK, ReturnCode: mqttsn.RejectedCongested},
		{Type: mqttsn.WILLTOPICREQ},
		{Type: mqttsn.WILLTOPIC, Flags: mqttsn.Flags{QoS: 1, Retain: true}, TopicName: "dev/1/state"},
		{Type: mqttsn.WILLTOPIC},
		{Type: mqttsn.WILLMSGREQ},
		{Type: mqttsn.WILLMSG, Data: []byte("offline")},
		{Type: mqttsn.REGISTER, TopicID: 0, MsgID: 5, TopicName: "a/b/c"},
		{Type: mqttsn.REGACK, TopicID: 9, MsgID: 5, ReturnCode: mqttsn.Accepted},
		{Type: mqttsn.PUBLISH, Flags: f, TopicID: 0x1234, MsgID: 0xBEEF, Data: []byte{1, 2, 3}},
		{Type: mqttsn.PUBLISH, Flags: mqttsn.Flags{QoS: -1, TopicIDType: mqttsn.TopicShort}, TopicID: 0x6162},
		{Type: mqttsn.PUBACK, TopicID: 1, MsgID: 2, ReturnCode: mqttsn.RejectedTopicID},
		{Type: mqttsn.PUBREC, MsgID: 10},
		{Type: mqttsn.PUBREL, MsgID: 11},
		{Type: mqttsn.PUBCOMP, MsgID: 12},
		{Type: mqttsn.SUBSCRIBE, Flags: mqttsn.Flags{QoS: 1}, MsgID: 3, TopicName: "cmd/+/set"},
		{Type: mqttsn.SUBSCRIBE, Flags: mqttsn.Flags{QoS: 2, TopicIDType: mqttsn.TopicPredefined}, MsgID: 4, TopicID: 17},
		{Type: mqttsn.SUBACK, Flags: mqttsn.Flags{QoS: 1}, TopicID: 4, MsgID: 3, ReturnCode: mqttsn.RejectedNotSupp},
		{Type: mqttsn.UNSUBSCRIBE, MsgID: 6, TopicName: "x/#"},
		{Type: mqttsn.UNSUBSCRIBE, Flags: mqttsn.Flags{TopicIDType: mqttsn.TopicShort}, MsgID: 7, TopicID: 0x7879},
		{Type: mqttsn.UNSUBACK, MsgID: 6},
		{Type: mqttsn.PINGREQ},
		{Type: mqttsn.PINGREQ, ClientID: "sleepy"},
		{Type: mqttsn.PINGRESP},
		{Type: mqttsn.DISCONNECT},
		{Type: mqttsn.DISCONNECT, HasDuration: true, Duration: 300},
		{Type: mqttsn.WILLTOPICUPD, Flags: mqttsn.Flags{QoS: 2}, TopicName: "t"},
		{Type: mqttsn.WILLTOPICUPD},
		{Type: mqttsn.WILLTOPICRESP, ReturnCode: mqttsn.Accepted},
		{Type: mqttsn.WILLMSGUPD, Data: []byte("bye")},
		{Type: mqttsn.WILLMSGRESP, ReturnCode: mqttsn.RejectedNotSupp},
	}
}

// Covers: SIG-IPE-470
func TestMQTTSNCodecRoundTrip(t *testing.T) {
	for _, m := range codecSamples() {
		b := m.Encode()
		got, err := mqttsn.Decode(b)
		if err != nil {
			t.Errorf("%s: decode: %v", m.Type, err)
			continue
		}
		if !reflect.DeepEqual(got, m) {
			t.Errorf("%s round trip:\n got %+v\nwant %+v", m.Type, got, m)
		}
		if int(b[0]) != len(b) {
			t.Errorf("%s: length byte %d, datagram %d bytes", m.Type, b[0], len(b))
		}
	}
	// Known bytes: CONNECT clean session, duration 30, client "ab".
	c := (&mqttsn.Message{Type: mqttsn.CONNECT, Flags: mqttsn.Flags{CleanSession: true}, Duration: 30, ClientID: "ab"}).Encode()
	if want := []byte{0x08, 0x04, 0x04, 0x01, 0x00, 0x1E, 'a', 'b'}; !bytes.Equal(c, want) {
		t.Errorf("CONNECT = % x, want % x", c, want)
	}
	// Flags: QoS -1 is 0b11 in bits 6-5; short topic is 0b10.
	if b := (mqttsn.Flags{QoS: -1, TopicIDType: mqttsn.TopicShort}).Byte(); b != 0x62 {
		t.Errorf("QoS -1 short-topic flags = %#x, want 0x62", b)
	}
	if f := mqttsn.ParseFlags(0x9C); !f.DUP || f.QoS != 0 || !f.Retain || !f.Will || !f.CleanSession {
		t.Errorf("ParseFlags(0x9C) = %+v", f)
	}
	// A message of 256 bytes or more uses 0x01 and a two-byte length.
	big := &mqttsn.Message{Type: mqttsn.PUBLISH, Flags: mqttsn.Flags{QoS: 1}, TopicID: 1, MsgID: 2, Data: []byte(strings.Repeat("x", 300))}
	b := big.Encode()
	if b[0] != 0x01 || int(b[1])<<8|int(b[2]) != len(b) || b[3] != byte(mqttsn.PUBLISH) {
		t.Errorf("long form header = % x (len %d)", b[:4], len(b))
	}
	if got, err := mqttsn.Decode(b); err != nil || !reflect.DeepEqual(got, big) {
		t.Errorf("long form round trip: %v", err)
	}
	// Short topic helpers.
	if id, ok := mqttsn.ShortTopic("ab"); !ok || id != 0x6162 || mqttsn.ShortName(id) != "ab" {
		t.Errorf("short topic ab = %#x", id)
	}
	// Truncated and inconsistent input is an error, not a panic.
	for _, in := range [][]byte{nil, {0x02}, {0x01, 0x00}, {0x05, 0x0C, 0x00}, {0x03, 0x0B, 0}, {0x01, 0x00, 0x02, 0x0C}, {0x02, 0xFE}, {0x09, 0x0C}} {
		if _, err := mqttsn.Decode(in); err == nil {
			t.Errorf("Decode(% x) accepted", in)
		}
	}
}

// Covers: SIG-IPE-470
func FuzzMQTTSNDecode(f *testing.F) {
	for _, m := range codecSamples() {
		f.Add(m.Encode())
	}
	f.Add([]byte{0x01, 0x00, 0x05, 0x0D, 0x00})
	f.Add([]byte{0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := mqttsn.Decode(b)
		if err != nil {
			return
		}
		// Whatever decodes re-encodes and decodes to the same message.
		m2, err := mqttsn.Decode(m.Encode())
		if err != nil {
			t.Fatalf("re-decode of %+v: %v", m, err)
		}
		if m.Type == mqttsn.CONNECT {
			m.ProtocolID = mqttsn.ProtocolID
		}
		if !reflect.DeepEqual(m, m2) {
			t.Fatalf("unstable: %+v vs %+v", m, m2)
		}
	})
}
