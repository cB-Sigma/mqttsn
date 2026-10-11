package sn2_test

import (
	"bytes"
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/cB-Sigma/mqttsn/sn2"
)

// The vectors are built by hand from the packet figures of OASIS MQTT-SN
// 2.0 draft CSD01 (the draft has no worked byte examples of its own).

// Draft clause 2.1.3: the packet type codes; clause 2.1.2: both length forms.
//
// Covers: SIG-IPE-3600
func TestTypesAndLength(t *testing.T) {
	want := map[sn2.Type]byte{
		sn2.CONNECT: 0x01, sn2.CONNACK: 0x02, sn2.PUBLISH: 0x03, sn2.PUBACK: 0x04, sn2.PUBREC: 0x05,
		sn2.PUBREL: 0x06, sn2.PUBCOMP: 0x07, sn2.SUBSCRIBE: 0x08, sn2.SUBACK: 0x09, sn2.UNSUBSCRIBE: 0x0A,
		sn2.UNSUBACK: 0x0B, sn2.PINGREQ: 0x0C, sn2.PINGRESP: 0x0D, sn2.DISCONNECT: 0x0E, sn2.AUTH: 0x0F,
		sn2.REGISTER: 0x10, sn2.REGACK: 0x11, sn2.PUBWOS: 0x12, sn2.SLEEPREQ: 0x13, sn2.SLEEPRESP: 0x14,
		sn2.WAKEUP: 0x15, sn2.ADVERTISE: 0x16, sn2.SEARCHGW: 0x17, sn2.GWINFO: 0x18,
		sn2.ForwarderEncapsulation: 0xFD, sn2.ConnectionEncapsulation: 0xFE, sn2.ProtectionEncapsulation: 0xFF,
	}
	for typ, v := range want {
		if byte(typ) != v {
			t.Errorf("%s = 0x%02X, want 0x%02X", typ, byte(typ), v)
		}
	}
	// Reserved codes are not decoded.
	for _, b := range []byte{0x00, 0x19, 0xFC} {
		if _, err := sn2.Decode([]byte{0x02, b}); err == nil {
			t.Errorf("type 0x%02X decoded", b)
		}
	}
	// 253 payload bytes + 2 (header) + 1 (flags) + 2 (alias) = 258: long form.
	p := &sn2.Packet{Type: sn2.PUBLISH, TopicType: sn2.TopicPredefined, TopicAlias: 1, Payload: bytes.Repeat([]byte{'x'}, 251)}
	b := p.Encode()
	if len(b) != 258 || b[0] != 0x01 || b[1] != 0x01 || b[2] != 0x02 || b[3] != 0x03 {
		t.Fatalf("long form % x…", b[:4])
	}
	got, err := sn2.Decode(b)
	if err != nil || len(got.Payload) != 251 {
		t.Fatalf("long form decode: %v", err)
	}
	// The short form read in the long encoding too (clause 2.1.2-1).
	if got, err := sn2.Decode([]byte{0x01, 0x00, 0x06, 0x0C, 0x12, 0x34}); err != nil || got.Type != sn2.PINGREQ || got.PacketID != 0x1234 {
		t.Errorf("long-form PINGREQ = %+v, %v", got, err)
	}
}

type vector struct {
	name string
	p    *sn2.Packet
	b    []byte
}

func check(t *testing.T, vs []vector) {
	t.Helper()
	for _, v := range vs {
		if got := v.p.Encode(); !bytes.Equal(got, v.b) {
			t.Errorf("%s: encode % x, want % x", v.name, got, v.b)
		}
		got, err := sn2.Decode(v.b)
		if err != nil {
			t.Errorf("%s: decode: %v", v.name, err)
			continue
		}
		if !reflect.DeepEqual(norm(got), norm(v.p)) {
			t.Errorf("%s: decode %+v, want %+v", v.name, got, v.p)
		}
	}
}

// norm clears the fields decode fills that a vector may leave unset.
func norm(p *sn2.Packet) sn2.Packet {
	c := *p
	c.HasReason = false
	if len(c.Payload) == 0 {
		c.Payload = nil
	}
	if c.Auth != nil && len(c.Auth.Data) == 0 {
		a := *c.Auth
		a.Data = nil
		c.Auth = &a
	}
	if c.Will != nil && len(c.Will.Payload) == 0 {
		w := *c.Will
		w.Payload = nil
		c.Will = &w
	}
	if len(c.Extra) == 0 {
		c.Extra = nil
	}
	if len(c.GwAdd) == 0 {
		c.GwAdd = nil
	}
	return c
}

// Draft clauses 3.1 (Figure 3-1) and 3.2 (Figure 3-3).
//
// Covers: SIG-IPE-3601, SIG-IPE-3602
func TestConnectConnack(t *testing.T) {
	check(t, []vector{
		{"CONNECT minimal (10 bytes, clause 3.1.7)",
			&sn2.Packet{Type: sn2.CONNECT, PacketID: 0x0102, Version: 2, KeepAlive: 60},
			[]byte{10, 0x01, 0x00, 0x01, 0x02, 0x02, 0x00, 0x3C, 0x00, 0x00}},
		{"CONNECT clean start, client ID",
			&sn2.Packet{Type: sn2.CONNECT, CleanStart: true, PacketID: 1, Version: 2, KeepAlive: 30, MaxPacketSize: 512, ClientID: "c1"},
			[]byte{12, 0x01, 0x01, 0x00, 0x01, 0x02, 0x00, 0x1E, 0x02, 0x00, 'c', '1'}},
		{"CONNECT every optional field",
			&sn2.Packet{Type: sn2.CONNECT, CleanStart: true, AllowAddrChange: true, AllowServerValues: true, PacketID: 7, Version: 2, KeepAlive: 10,
				HasDefaultAwake: true, DefaultAwake: 3, HasSessionExpiry: true, SessionExpiry: 0x00010000,
				Will: &sn2.Will{TopicType: sn2.TopicName, QoS: 1, Retain: true, TopicName: "w/t", Payload: []byte("bye")},
				Auth: &sn2.Auth{Method: "MQTT-BASIC", Data: []byte{0, 1, 'u', 0, 1, 'p'}}, ClientID: "id"},
			[]byte{
				47, 0x01,
				0x7F,             // Srv Sugg, Net Addr, DAM, Sess Exp, Auth, Will, Clean Start
				0x17,             // Will Retain, Will QoS 1, Will Topic Type 0b11
				0x00, 0x07, 0x02, // Packet Identifier, Protocol Version
				0x00, 0x0A, 0x00, 0x00, // Keep Alive, Maximum Packet Size
				0x03,                   // Default Awake Messages
				0x00, 0x01, 0x00, 0x00, // Session Expiry Interval
				0x00, 0x03, 'w', '/', 't', 0x00, 0x03, 'b', 'y', 'e', // Will
				10, 'M', 'Q', 'T', 'T', '-', 'B', 'A', 'S', 'I', 'C', 0x00, 0x06, 0, 1, 'u', 0, 1, 'p', // Auth
				'i', 'd'}},
		{"CONNECT will on a predefined alias",
			&sn2.Packet{Type: sn2.CONNECT, PacketID: 1, Version: 2, KeepAlive: 1,
				Will: &sn2.Will{TopicType: sn2.TopicPredefined, QoS: 2, TopicAlias: 5, Payload: []byte{9}}},
			[]byte{16, 0x01, 0x02, 0x09, 0x00, 0x01, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 9}},
		{"CONNACK success, session present",
			&sn2.Packet{Type: sn2.CONNACK, SessionPresent: true, PacketID: 0x0102},
			[]byte{6, 0x02, 0x01, 0x01, 0x02, 0x00}},
		{"CONNACK every optional field",
			&sn2.Packet{Type: sn2.CONNACK, HasSessionExpiry: true, SessionExpiry: 300, HasServerKeepAlive: true, ServerKeepAlive: 20,
				PacketID: 9, Auth: &sn2.Auth{Method: "M"}, ClientID: "sn2-x"},
			[]byte{21, 0x02, 0x0E, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x14, 1, 'M', 0x00, 0x00, 's', 'n', '2', '-', 'x'}},
		{"CONNACK refusal",
			&sn2.Packet{Type: sn2.CONNACK, PacketID: 3, Reason: sn2.UnsupportedVersion},
			[]byte{6, 0x02, 0x00, 0x00, 0x03, 0x84}},
	})
	// Clause 3.1.2-1: the reserved Connect Flags bit is reported.
	if p, err := sn2.Decode([]byte{10, 0x01, 0x80, 0x00, 0x01, 0x02, 0x00, 0x3C, 0x00, 0x00}); err != nil || !p.Reserved {
		t.Errorf("reserved connect flag: %+v, %v", p, err)
	}
	// Will QoS 3 is malformed (clause 3.1.3.2).
	if p, err := sn2.Decode([]byte{15, 0x01, 0x02, 0x0F, 0x00, 0x01, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil || !p.Reserved {
		t.Errorf("will QoS 3: %+v, %v", p, err)
	}
	// Truncated optional fields are refused.
	if _, err := sn2.Decode([]byte{11, 0x01, 0x08, 0x00, 0x01, 0x02, 0x00, 0x3C, 0x00, 0x00, 0x00}); err == nil {
		t.Error("CONNECT with a truncated Session Expiry Interval decoded")
	}
}

// Draft clauses 3.4 (Figure 3-5) and 3.5 (Figure 3-6).
//
// Covers: SIG-IPE-3603
func TestRegisterRegack(t *testing.T) {
	check(t, []vector{
		{"REGISTER from a client (no alias)", &sn2.Packet{Type: sn2.REGISTER, PacketID: 1, TopicName: "a/b"}, []byte{8, 0x10, 0x00, 0x00, 0x01, 'a', '/', 'b'}},
		{"REGISTER from the gateway", &sn2.Packet{Type: sn2.REGISTER, PacketID: 2, HasTopicAlias: true, TopicAlias: 0x0203, TopicName: "t"},
			[]byte{8, 0x10, 0x01, 0x00, 0x02, 0x02, 0x03, 't'}},
		{"REGACK session alias", &sn2.Packet{Type: sn2.REGACK, TopicType: sn2.TopicSession, HasTopicAlias: true, TopicAlias: 5, PacketID: 1},
			[]byte{7, 0x11, 0x04, 0x00, 0x01, 0x00, 0x05}},
		{"REGACK predefined, Topic Alias Exists", &sn2.Packet{Type: sn2.REGACK, TopicType: sn2.TopicPredefined, HasTopicAlias: true, TopicAlias: 1, PacketID: 1, Reason: sn2.TopicAliasExists},
			[]byte{8, 0x11, 0x05, 0x00, 0x01, 0x00, 0x01, 0x1A}},
		{"REGACK from a client", &sn2.Packet{Type: sn2.REGACK, PacketID: 4}, []byte{5, 0x11, 0x00, 0x00, 0x04}},
	})
	if p, _ := sn2.Decode([]byte{5, 0x11, 0x80, 0x00, 0x04}); p == nil || !p.Reserved {
		t.Error("reserved REGACK flag not reported")
	}
}

// Draft clause 3.6 (Figures 3-8 to 3-16).
//
// Covers: SIG-IPE-3604
func TestPublishFamily(t *testing.T) {
	check(t, []vector{
		{"PUBWOS by name, retained", &sn2.Packet{Type: sn2.PUBWOS, TopicType: sn2.TopicName, Retain: true, TopicName: "s/t", Payload: []byte("v")},
			[]byte{9, 0x12, 0x13, 0x00, 0x03, 's', '/', 't', 'v'}},
		{"PUBWOS predefined", &sn2.Packet{Type: sn2.PUBWOS, TopicType: sn2.TopicPredefined, TopicAlias: 1, Payload: []byte{1, 2}},
			[]byte{7, 0x12, 0x01, 0x00, 0x01, 1, 2}},
		{"PUBLISH QoS 0 session alias (no packet identifier)", &sn2.Packet{Type: sn2.PUBLISH, TopicType: sn2.TopicSession, TopicAlias: 9, Payload: []byte("x")},
			[]byte{6, 0x03, 0x00, 0x00, 0x09, 'x'}},
		{"PUBLISH QoS 1 by name", &sn2.Packet{Type: sn2.PUBLISH, QoS: 1, TopicType: sn2.TopicName, PacketID: 0x0A0B, TopicName: "ab", Payload: []byte("p")},
			[]byte{10, 0x03, 0x23, 0x0A, 0x0B, 0x00, 0x02, 'a', 'b', 'p'}},
		{"PUBLISH QoS 2 DUP retain predefined", &sn2.Packet{Type: sn2.PUBLISH, DUP: true, QoS: 2, Retain: true, TopicType: sn2.TopicPredefined, PacketID: 1, TopicAlias: 2},
			[]byte{7, 0x03, 0xD1, 0x00, 0x01, 0x00, 0x02}},
		{"PUBACK without reason", &sn2.Packet{Type: sn2.PUBACK, PacketID: 5}, []byte{4, 0x04, 0x00, 0x05}},
		{"PUBACK unknown topic alias", &sn2.Packet{Type: sn2.PUBACK, PacketID: 5, Reason: sn2.UnknownTopicAlias}, []byte{5, 0x04, 0x00, 0x05, 0xF0}},
		{"PUBREC", &sn2.Packet{Type: sn2.PUBREC, PacketID: 6}, []byte{4, 0x05, 0x00, 0x06}},
		{"PUBREL", &sn2.Packet{Type: sn2.PUBREL, PacketID: 6}, []byte{4, 0x06, 0x00, 0x06}},
		{"PUBCOMP not found", &sn2.Packet{Type: sn2.PUBCOMP, PacketID: 6, Reason: sn2.PacketIDNotFound}, []byte{5, 0x07, 0x00, 0x06, 0x92}},
	})
	// An absent reason is Success (clause 3.6.4.3); present is reported.
	if p, _ := sn2.Decode([]byte{5, 0x04, 0x00, 0x05, 0x00}); p == nil || !p.HasReason || p.Reason != 0 {
		t.Errorf("PUBACK with an explicit Success: %+v", p)
	}
	// DUP on QoS 1, QoS 3 and a reserved bit are reported (clauses 3.6.3.2.3-1, 3.6.3.2).
	for _, f := range []byte{0xA3, 0x63, 0x07} {
		if p, err := sn2.Decode([]byte{9, 0x03, f, 0x00, 0x01, 0x00, 0x01, 'x', 'y'}); err != nil || !p.Reserved {
			t.Errorf("flags 0x%02X: %+v, %v", f, p, err)
		}
	}
	// A topic name longer than the packet is refused.
	if _, err := sn2.Decode([]byte{7, 0x03, 0x03, 0x00, 0x09, 'a', 'b'}); err == nil {
		t.Error("PUBLISH with a truncated topic name decoded")
	}
}

// Draft clauses 3.7 to 3.10 (Figures 3-17 to 3-20).
//
// Covers: SIG-IPE-3605
func TestSubscribeFamily(t *testing.T) {
	check(t, []vector{
		{"SUBSCRIBE filter with every option", &sn2.Packet{Type: sn2.SUBSCRIBE, NoLocal: true, QoS: 2, RetainAsPublished: true, RetainHandling: 2, TopicType: sn2.TopicName, PacketID: 3, TopicName: "a/#"},
			[]byte{8, 0x08, 0xDB, 0x00, 0x03, 'a', '/', '#'}},
		{"SUBSCRIBE predefined QoS 1", &sn2.Packet{Type: sn2.SUBSCRIBE, QoS: 1, TopicType: sn2.TopicPredefined, PacketID: 4, TopicAlias: 2},
			[]byte{7, 0x08, 0x21, 0x00, 0x04, 0x00, 0x02}},
		{"SUBACK session alias granted QoS 1", &sn2.Packet{Type: sn2.SUBACK, TopicType: sn2.TopicSession, HasTopicAlias: true, TopicAlias: 7, PacketID: 3, Reason: sn2.GrantedQoS1},
			[]byte{8, 0x09, 0x04, 0x00, 0x03, 0x00, 0x07, 0x01}},
		{"SUBACK wildcard, no alias", &sn2.Packet{Type: sn2.SUBACK, TopicType: sn2.TopicPredefined, PacketID: 3, Reason: sn2.GrantedQoS2},
			[]byte{6, 0x09, 0x01, 0x00, 0x03, 0x02}},
		{"UNSUBSCRIBE filter", &sn2.Packet{Type: sn2.UNSUBSCRIBE, TopicType: sn2.TopicName, PacketID: 5, TopicName: "a/+"},
			[]byte{8, 0x0A, 0x03, 0x00, 0x05, 'a', '/', '+'}},
		{"UNSUBSCRIBE session alias", &sn2.Packet{Type: sn2.UNSUBSCRIBE, TopicType: sn2.TopicSession, PacketID: 5, TopicAlias: 1},
			[]byte{7, 0x0A, 0x00, 0x00, 0x05, 0x00, 0x01}},
		{"UNSUBACK no subscription", &sn2.Packet{Type: sn2.UNSUBACK, PacketID: 5, Reason: sn2.NoSubscriptionExisted}, []byte{5, 0x0B, 0x00, 0x05, 0x11}},
	})
	// Retain Handling 3 and QoS 3 are protocol errors (clauses 3.7.2.2, 3.7.2.4).
	for _, f := range []byte{0x0F, 0x63} {
		if p, _ := sn2.Decode([]byte{6, 0x08, f, 0x00, 0x01, 'a'}); p == nil || !p.Reserved {
			t.Errorf("SUBSCRIBE flags 0x%02X not reported", f)
		}
	}
}

// Draft clauses 3.3 and 3.11 to 3.16.
//
// Covers: SIG-IPE-3606
func TestSessionPackets(t *testing.T) {
	check(t, []vector{
		{"AUTH", &sn2.Packet{Type: sn2.AUTH, PacketID: 1, Reason: sn2.ContinueAuthentication, Auth: &sn2.Auth{Method: "S", Data: []byte{1, 2}}},
			[]byte{9, 0x0F, 0x00, 0x01, 0x18, 1, 'S', 1, 2}},
		{"PINGREQ", &sn2.Packet{Type: sn2.PINGREQ, PacketID: 0xBEEF}, []byte{4, 0x0C, 0xBE, 0xEF}},
		{"PINGRESP", &sn2.Packet{Type: sn2.PINGRESP, PacketID: 1}, []byte{4, 0x0D, 0x00, 0x01}},
		{"PINGRESP messages remaining", &sn2.Packet{Type: sn2.PINGRESP, PacketID: 1, HasRemaining: true, Remaining: 255}, []byte{5, 0x0D, 0x00, 0x01, 0xFF}},
		{"DISCONNECT bare", &sn2.Packet{Type: sn2.DISCONNECT}, []byte{3, 0x0E, 0x00}},
		{"DISCONNECT every field", &sn2.Packet{Type: sn2.DISCONNECT, HasPacketID: true, PacketID: 2, HasSessionExpiry: true, SessionExpiry: 60, HasReason: true, Reason: sn2.NoVirtualConnection, ReasonString: "no"},
			[]byte{12, 0x0E, 0x07, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3C, 0xF4, 'n', 'o'}},
		{"DISCONNECT with will", &sn2.Packet{Type: sn2.DISCONNECT, HasReason: true, Reason: sn2.DisconnectWithWill}, []byte{4, 0x0E, 0x04, 0x04}},
		{"WAKEUP", &sn2.Packet{Type: sn2.WAKEUP}, []byte{2, 0x15}},
		{"SLEEPREQ", &sn2.Packet{Type: sn2.SLEEPREQ, RetainAliases: true, PacketID: 3, SleepDuration: 3600}, []byte{9, 0x13, 0x01, 0x00, 0x03, 0x00, 0x00, 0x0E, 0x10}},
		{"SLEEPRESP", &sn2.Packet{Type: sn2.SLEEPRESP, PacketID: 3}, []byte{5, 0x14, 0x00, 0x00, 0x03}},
		{"SLEEPRESP modified duration", &sn2.Packet{Type: sn2.SLEEPRESP, HasSleepDuration: true, SleepDuration: 10, PacketID: 3, Reason: sn2.Success, HasReason: true},
			[]byte{10, 0x14, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0A, 0x00}},
	})
	// A two-byte DISCONNECT (no flags) is read as all absent.
	if p, err := sn2.Decode([]byte{2, 0x0E}); err != nil || p.HasReason {
		t.Errorf("two-byte DISCONNECT: %+v, %v", p, err)
	}
}

// Draft clauses 3.18 to 3.20.
//
// Covers: SIG-IPE-3607
func TestDiscoveryAndEnvelopes(t *testing.T) {
	check(t, []vector{
		{"ADVERTISE", &sn2.Packet{Type: sn2.ADVERTISE, GwID: 7, Duration: 900}, []byte{5, 0x16, 7, 0x03, 0x84}},
		{"SEARCHGW", &sn2.Packet{Type: sn2.SEARCHGW}, []byte{2, 0x17}},
		{"SEARCHGW radius", &sn2.Packet{Type: sn2.SEARCHGW, Extra: []byte{1}}, []byte{3, 0x17, 1}},
		{"GWINFO", &sn2.Packet{Type: sn2.GWINFO, GwID: 7}, []byte{3, 0x18, 7}},
		{"GWINFO address", &sn2.Packet{Type: sn2.GWINFO, GwID: 7, GwAdd: []byte{10, 0, 0, 1}}, []byte{7, 0x18, 7, 10, 0, 0, 1}},
	})
	inner := (&sn2.Packet{Type: sn2.PINGREQ, PacketID: 1}).Encode()
	env := append(sn2.Envelope(sn2.ForwarderEncapsulation, []byte{0xAA, 0xBB}), inner...)
	if !bytes.Equal(env, []byte{4, 0xFD, 0xAA, 0xBB, 4, 0x0C, 0x00, 0x01}) {
		t.Errorf("forwarder envelope % x", env)
	}
	info, in, ok := sn2.Unwrap(env, sn2.ForwarderEncapsulation)
	if !ok || !bytes.Equal(info, []byte{0xAA, 0xBB}) || !bytes.Equal(in, inner) {
		t.Errorf("unwrap = % x, % x, %v", info, in, ok)
	}
	env = append(sn2.Envelope(sn2.ConnectionEncapsulation, []byte("dev")), inner...)
	if info, _, ok := sn2.Unwrap(env, sn2.ConnectionEncapsulation); !ok || string(info) != "dev" {
		t.Errorf("connection envelope % x", env)
	}
	if _, _, ok := sn2.Unwrap(inner, sn2.ForwarderEncapsulation); ok {
		t.Error("a plain packet unwrapped")
	}
	// MQTT-BASIC authentication data (clause 4.11.1.2).
	d := sn2.BasicData("user", []byte("pw"))
	if !bytes.Equal(d, []byte{0, 4, 'u', 's', 'e', 'r', 0, 2, 'p', 'w'}) {
		t.Errorf("MQTT-BASIC data % x", d)
	}
	if u, pw, ok := sn2.BasicCredentials(d); !ok || u != "user" || string(pw) != "pw" {
		t.Errorf("credentials %q %q %v", u, pw, ok)
	}
	if _, _, ok := sn2.BasicCredentials([]byte{0, 9, 'x'}); ok {
		t.Error("truncated credentials accepted")
	}
}

// Decode never panics and reports a non-UTF-8 string.
//
// Covers: SIG-IPE-3608
func TestDecodeRobust(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 200000 {
		b := make([]byte, r.IntN(40))
		for i := range b {
			b[i] = byte(r.IntN(256))
		}
		if len(b) > 1 && r.IntN(2) == 0 {
			b[0] = byte(len(b))
			b[1] = byte(r.IntN(0x19))
		}
		_, _ = sn2.Decode(b)
	}
	for _, b := range [][]byte{nil, {0x01}, {0x01, 0x00}, {0x05, 0x03}, {0x01, 0x00, 0x02, 0x03}, {0x03, 0x01, 0x40}} {
		if _, err := sn2.Decode(b); err == nil {
			t.Errorf("% x decoded", b)
		}
	}
	if p, err := sn2.Decode([]byte{7, 0x10, 0x00, 0x00, 0x01, 0xFF, 0xFE}); err != nil || !p.BadUTF8 {
		t.Errorf("REGISTER with a non-UTF-8 name: %+v, %v", p, err)
	}
}
