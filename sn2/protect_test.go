package sn2_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cB-Sigma/mqttsn/sn2"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// AES-CMAC against the examples of RFC 4493 section 4.
//
// Covers: SIG-IPE-3626
func TestCMACVectors(t *testing.T) {
	key := unhex("2b7e151628aed2a6abf7158809cf4f3c")
	msg := unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	for _, v := range []struct {
		n   int
		tag string
	}{
		{0, "bb1d6929e95937287fa37d129b756746"},
		{16, "070a16b46b4d4144f79bdd9dd04a287c"},
		{40, "dfa66747de9ae63030ca32611497c827"},
		{64, "51f0bebf7e3b9d92fc49741779363cfe"},
	} {
		got, err := sn2.CMAC(key, msg[:v.n])
		if err != nil || hex.EncodeToString(got) != v.tag {
			t.Errorf("CMAC over %d bytes = %x, %v; want %s", v.n, got, err, v.tag)
		}
	}
}

// Protection Encapsulation (draft clause 3.17): every scheme of Figure
// 3-29 round-trips; a changed byte, a wrong key, an unknown sender,
// unknown schemes and reserved lengths are refused; the layout follows
// Figure 3-28.
//
// Covers: SIG-IPE-3626
func TestProtection(t *testing.T) {
	inner := (&sn2.Packet{Type: sn2.PINGREQ, PacketID: 7}).Encode()
	sender := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	keys := map[int][]byte{16: bytes.Repeat([]byte{0x11}, 16), 24: bytes.Repeat([]byte{0x22}, 24), 32: bytes.Repeat([]byte{0x33}, 32), 0: []byte("any length key")}
	for _, sc := range []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49} {
		key := keys[sn2.SchemeKeyLen(sc)]
		for _, v := range []struct {
			crypto []byte
			ctr    int
			tag    byte
		}{{nil, 0, 1}, {make([]byte, 12), 4, 1}, {[]byte{9, 9}, 2, 1}, {[]byte{1, 2, 3, 4}, 0, 4}} {
			if v.tag == 4 && !sn2.SchemeAuthOnly(sc) {
				continue
			}
			p := sn2.Protection{Scheme: sc, SenderID: sender, Random: [4]byte{0xA, 0xB, 0xC, 0xD}, Crypto: v.crypto, CounterLen: v.ctr, Counter: 0x01020304, TagCode: v.tag}
			b, err := sn2.Protect(key, p, inner)
			if err != nil {
				t.Fatalf("%s: %v", sn2.SchemeName(sc), err)
			}
			if b[0] != byte(len(b)) || b[1] != 0xFF || b[3] != sc || !bytes.Equal(b[4:12], sender[:]) || !bytes.Equal(b[12:16], []byte{0xA, 0xB, 0xC, 0xD}) {
				t.Fatalf("%s: header % x", sn2.SchemeName(sc), b[:16])
			}
			if !sn2.SchemeAuthOnly(sc) && bytes.Contains(b, inner) {
				t.Errorf("%s: the packet is not encrypted", sn2.SchemeName(sc))
			}
			got, out, err := sn2.Unprotect(b, func(id [8]byte) ([]byte, bool) { return key, id == sender })
			if err != nil || !bytes.Equal(out, inner) || got.Scheme != sc || (v.ctr > 0 && got.Counter&0xFFFF != 0x0304) {
				t.Fatalf("%s %+v: %v, % x", sn2.SchemeName(sc), v, err, out)
			}
			bad := append([]byte(nil), b...)
			bad[len(bad)-1] ^= 1
			if _, _, err := sn2.Unprotect(bad, func([8]byte) ([]byte, bool) { return key, true }); !errors.Is(err, sn2.ErrAuthentication) {
				t.Errorf("%s: a changed tag gave %v", sn2.SchemeName(sc), err)
			}
		}
	}
	key := keys[32]
	b, _ := sn2.Protect(key, sn2.Protection{Scheme: sn2.SchemeHMACSHA256, SenderID: sender}, inner)
	if _, _, err := sn2.Unprotect(b, func([8]byte) ([]byte, bool) { return nil, false }); !errors.Is(err, sn2.ErrUnknownSender) {
		t.Errorf("unknown sender: %v", err)
	}
	if _, _, err := sn2.Unprotect(b, func([8]byte) ([]byte, bool) { return keys[16], true }); !errors.Is(err, sn2.ErrAuthentication) {
		t.Errorf("wrong key: %v", err)
	}
	for _, mut := range []func([]byte){
		func(x []byte) { x[3] = 0x05 },            // reserved scheme
		func(x []byte) { x[2] = x[2]&0xF0 | 0x3 }, // counter length 3
		func(x []byte) { x[2] = 0x20 },            // tag length 2
	} {
		x := append([]byte(nil), b...)
		mut(x)
		if _, _, err := sn2.Unprotect(x, func([8]byte) ([]byte, bool) { return key, true }); err == nil {
			t.Errorf("% x accepted", x[:4])
		}
	}
	// A long packet uses the three-byte length.
	big := (&sn2.Packet{Type: sn2.PUBLISH, TopicType: sn2.TopicPredefined, TopicAlias: 1, Payload: bytes.Repeat([]byte{1}, 300)}).Encode()
	lb, err := sn2.Protect(key, sn2.Protection{Scheme: sn2.SchemeGCM256, SenderID: sender}, big)
	if err != nil || lb[0] != 0x01 || int(lb[1])<<8|int(lb[2]) != len(lb) {
		t.Fatalf("long form % x, %v", lb[:4], err)
	}
	if _, out, err := sn2.Unprotect(lb, func([8]byte) ([]byte, bool) { return key, true }); err != nil || !bytes.Equal(out, big) {
		t.Errorf("long form: %v", err)
	}
}
