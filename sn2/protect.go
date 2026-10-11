package sn2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/cB-Sigma/iotcrypto/ccm"
)

// Protection Encapsulation (draft clause 3.17): Length, type 0xFF,
// Protection Flags, Protection Scheme, an 8-byte Sender Identifier, a
// 4-byte Random, optional Cryptographic Material (2, 4 or 12 bytes) and
// Monotonic Counter (2 or 4 bytes), the protected packet, then the
// Authentication Tag. Unlike the other envelopes, Length covers the whole
// datagram, tag included (F-2072).
//
// Authentication-only schemes (HMAC, CMAC) compute the tag over every
// byte before it. AEAD schemes (AES-CCM, AES-GCM, ChaCha20-Poly1305)
// encrypt the protected packet, with every byte before it as associated
// data and the nonce taken from SHA-256 of those bytes (clauses 3.17.3-2
// to -4); the draft does not say what the AEAD encrypts (F-2071).

// Protection schemes (draft Figure 3-29).
const (
	SchemeHMACSHA256  byte = 0x00
	SchemeHMACSHA3256 byte = 0x01
	SchemeCMAC128     byte = 0x02
	SchemeCMAC192     byte = 0x03
	SchemeCMAC256     byte = 0x04
	SchemeCCM64_128   byte = 0x40
	SchemeCCM64_192   byte = 0x41
	SchemeCCM64_256   byte = 0x42
	SchemeCCM128_128  byte = 0x43
	SchemeCCM128_192  byte = 0x44
	SchemeCCM128_256  byte = 0x45
	SchemeGCM128      byte = 0x46
	SchemeGCM192      byte = 0x47
	SchemeGCM256      byte = 0x48
	SchemeChaCha20    byte = 0x49
)

type scheme struct {
	name     string
	authOnly bool
	keyLen   int // 0: any
	tagLen   int // nominal, bytes
}

var schemes = map[byte]scheme{
	SchemeHMACSHA256:  {"HMAC-SHA256", true, 0, 32},
	SchemeHMACSHA3256: {"HMAC-SHA3-256", true, 0, 32},
	SchemeCMAC128:     {"CMAC-128", true, 16, 16},
	SchemeCMAC192:     {"CMAC-192", true, 24, 16},
	SchemeCMAC256:     {"CMAC-256", true, 32, 16},
	SchemeCCM64_128:   {"AES-CCM-64-128", false, 16, 8},
	SchemeCCM64_192:   {"AES-CCM-64-192", false, 24, 8},
	SchemeCCM64_256:   {"AES-CCM-64-256", false, 32, 8},
	SchemeCCM128_128:  {"AES-CCM-128-128", false, 16, 16},
	SchemeCCM128_192:  {"AES-CCM-128-192", false, 24, 16},
	SchemeCCM128_256:  {"AES-CCM-128-256", false, 32, 16},
	SchemeGCM128:      {"AES-GCM-128-128", false, 16, 16},
	SchemeGCM192:      {"AES-GCM-128-192", false, 24, 16},
	SchemeGCM256:      {"AES-GCM-128-256", false, 32, 16},
	SchemeChaCha20:    {"ChaCha20-Poly1305", false, 32, 16},
}

// SchemeName names a protection scheme ("" if the gateway does not know it).
func SchemeName(s byte) string { return schemes[s].name }

// SchemeKeyLen is the key length a scheme needs in bytes (0: any; -1: unknown).
func SchemeKeyLen(s byte) int {
	sc, ok := schemes[s]
	if !ok {
		return -1
	}
	return sc.keyLen
}

// SchemeAuthOnly reports an authentication-only scheme.
func SchemeAuthOnly(s byte) bool { return schemes[s].authOnly }

// Protection is the header of a Protection Encapsulation.
type Protection struct {
	Scheme   byte
	SenderID [8]byte
	Random   [4]byte
	// Crypto is the Cryptographic Material: 0, 2, 4 or 12 bytes.
	Crypto []byte
	// CounterLen is 0, 2 or 4; Counter the Monotonic Counter.
	CounterLen int
	Counter    uint32
	// TagCode is the Authentication Tag Length field: 1 (nominal) or,
	// for authentication-only schemes, 4 to 15 (a tag of 2 × code bytes).
	TagCode byte
}

// Protection errors.
var (
	ErrUnknownSender  = errors.New("mqtt-sn 2.0 protection: unknown Sender Identifier")
	ErrScheme         = errors.New("mqtt-sn 2.0 protection: protection scheme not supported")
	ErrAuthentication = errors.New("mqtt-sn 2.0 protection: the packet does not authenticate")
	ErrProtection     = errors.New("mqtt-sn 2.0 protection: malformed Protection Encapsulation")
)

func (p *Protection) tagLen(sc scheme) (int, error) {
	switch {
	case p.TagCode == 1:
		return sc.tagLen, nil
	case p.TagCode >= 4 && sc.authOnly:
		n := int(p.TagCode) * 2
		if n > sc.tagLen {
			return 0, fmt.Errorf("%w: a %d-byte tag is longer than %s's", ErrProtection, n, sc.name)
		}
		return n, nil
	}
	// 0 (provider defined), 2 and 3 (reserved), or truncation of an AEAD.
	return 0, fmt.Errorf("%w: Authentication Tag Length %d", ErrProtection, p.TagCode)
}

func cryptoCode(n int) (byte, bool) {
	switch n {
	case 0:
		return 0, true
	case 2:
		return 1, true
	case 4:
		return 2, true
	case 12:
		return 3, true
	}
	return 0, false
}

func counterCode(n int) (byte, bool) {
	switch n {
	case 0:
		return 0, true
	case 2:
		return 1, true
	case 4:
		return 2, true
	}
	return 0, false
}

// header writes everything before the protected packet for a datagram
// whose total length is total.
func (p *Protection) header(total int) ([]byte, error) {
	cc, ok := cryptoCode(len(p.Crypto))
	mc, ok2 := counterCode(p.CounterLen)
	if !ok || !ok2 {
		return nil, fmt.Errorf("%w: material %d bytes, counter %d bytes", ErrProtection, len(p.Crypto), p.CounterLen)
	}
	var h []byte
	if total < 256 {
		h = []byte{byte(total), byte(ProtectionEncapsulation)}
	} else {
		h = []byte{0x01, byte(total >> 8), byte(total), byte(ProtectionEncapsulation)}
	}
	h = append(h, p.TagCode<<4|cc<<2|mc, p.Scheme)
	h = append(h, p.SenderID[:]...)
	h = append(h, p.Random[:]...)
	h = append(h, p.Crypto...)
	switch p.CounterLen {
	case 2:
		h = binary.BigEndian.AppendUint16(h, uint16(p.Counter))
	case 4:
		h = binary.BigEndian.AppendUint32(h, p.Counter)
	}
	return h, nil
}

// Protect wraps packet in a Protection Encapsulation with key.
func Protect(key []byte, p Protection, packet []byte) ([]byte, error) {
	sc, ok := schemes[p.Scheme]
	if !ok {
		return nil, ErrScheme
	}
	if sc.keyLen != 0 && len(key) != sc.keyLen {
		return nil, fmt.Errorf("%s needs a %d-byte key, not %d", sc.name, sc.keyLen, len(key))
	}
	if p.TagCode == 0 {
		p.TagCode = 1
	}
	tl, err := p.tagLen(sc)
	if err != nil {
		return nil, err
	}
	hl := 16 + len(p.Crypto) + p.CounterLen
	total := hl + len(packet) + tl
	if total >= 256 {
		total += 2
	}
	h, err := p.header(total)
	if err != nil {
		return nil, err
	}
	if sc.authOnly {
		out := append(h, packet...)
		tag, err := mac(p.Scheme, key, out)
		if err != nil {
			return nil, err
		}
		return append(out, tag[:tl]...), nil
	}
	aead, nonce, err := aeadFor(p.Scheme, key, h)
	if err != nil {
		return nil, err
	}
	return aead.Seal(h, nonce, packet, h), nil
}

// Unprotect checks and removes a Protection Encapsulation. keyFor returns
// the key shared with a sender; the header is returned even on an
// authentication failure, so the caller can tell who claimed to send it.
func Unprotect(b []byte, keyFor func(sender [8]byte) ([]byte, bool)) (Protection, []byte, error) {
	var p Protection
	n, hdr, ok := Header(b)
	if !ok || n > len(b) || Type(b[hdr]) != ProtectionEncapsulation {
		return p, nil, ErrProtection
	}
	b = b[:n]
	r := b[hdr+1:]
	if len(r) < 14 {
		return p, nil, ErrProtection
	}
	flags := r[0]
	p.Scheme, p.TagCode = r[1], flags>>4
	copy(p.SenderID[:], r[2:10])
	copy(p.Random[:], r[10:14])
	r = r[14:]
	cl := []int{0, 2, 4, 12}[flags>>2&0x03]
	switch flags & 0x03 {
	case 1:
		p.CounterLen = 2
	case 2:
		p.CounterLen = 4
	case 3:
		return p, nil, fmt.Errorf("%w: Monotonic Counter Length 3 is reserved", ErrProtection)
	}
	if len(r) < cl+p.CounterLen {
		return p, nil, ErrProtection
	}
	p.Crypto = append([]byte(nil), r[:cl]...)
	r = r[cl:]
	switch p.CounterLen {
	case 2:
		p.Counter = uint32(binary.BigEndian.Uint16(r))
	case 4:
		p.Counter = binary.BigEndian.Uint32(r)
	}
	r = r[p.CounterLen:]
	hl := len(b) - len(r)
	sc, ok := schemes[p.Scheme]
	if !ok {
		return p, nil, ErrScheme
	}
	tl, err := p.tagLen(sc)
	if err != nil {
		return p, nil, err
	}
	if len(r) < tl {
		return p, nil, ErrProtection
	}
	key, ok := keyFor(p.SenderID)
	if !ok {
		return p, nil, ErrUnknownSender
	}
	if sc.keyLen != 0 && len(key) != sc.keyLen {
		return p, nil, fmt.Errorf("%w: the key for this sender does not fit %s", ErrScheme, sc.name)
	}
	if sc.authOnly {
		body := b[:len(b)-tl]
		want, err := mac(p.Scheme, key, body)
		if err != nil {
			return p, nil, err
		}
		if subtle.ConstantTimeCompare(want[:tl], b[len(b)-tl:]) != 1 {
			return p, nil, ErrAuthentication
		}
		return p, append([]byte(nil), b[hl:len(b)-tl]...), nil
	}
	h := b[:hl]
	aead, nonce, err := aeadFor(p.Scheme, key, h)
	if err != nil {
		return p, nil, err
	}
	inner, err := aead.Open(nil, nonce, b[hl:], h)
	if err != nil {
		return p, nil, ErrAuthentication
	}
	return p, inner, nil
}

func mac(s byte, key, msg []byte) ([]byte, error) {
	var h func() hash.Hash
	switch s {
	case SchemeHMACSHA256:
		h = sha256.New
	case SchemeHMACSHA3256:
		h = func() hash.Hash { return sha3.New256() }
	case SchemeCMAC128, SchemeCMAC192, SchemeCMAC256:
		return CMAC(key, msg)
	default:
		return nil, ErrScheme
	}
	m := hmac.New(h, key)
	m.Write(msg)
	return m.Sum(nil), nil
}

func aeadFor(s byte, key, header []byte) (cipher.AEAD, []byte, error) {
	sum := sha256.Sum256(header)
	switch s {
	case SchemeCCM64_128, SchemeCCM64_192, SchemeCCM64_256, SchemeCCM128_128, SchemeCCM128_192, SchemeCCM128_256:
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, err
		}
		a, err := ccm.New(blk, 13, schemes[s].tagLen)
		return a, sum[:13], err
	case SchemeGCM128, SchemeGCM192, SchemeGCM256:
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, err
		}
		a, err := cipher.NewGCM(blk)
		return a, sum[:12], err
	case SchemeChaCha20:
		a, err := chacha20poly1305.New(key)
		return a, sum[:12], err
	}
	return nil, nil, ErrScheme
}

// CMAC is AES-CMAC (RFC 4493) with a 16, 24 or 32-byte key.
func CMAC(key, msg []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var l, k1, k2 [16]byte
	blk.Encrypt(l[:], l[:])
	dbl := func(dst, src *[16]byte) {
		var carry byte
		for i := 15; i >= 0; i-- {
			dst[i] = src[i]<<1 | carry
			carry = src[i] >> 7
		}
		if src[0]&0x80 != 0 {
			dst[15] ^= 0x87
		}
	}
	dbl(&k1, &l)
	dbl(&k2, &k1)
	n := (len(msg) + 15) / 16
	complete := n > 0 && len(msg)%16 == 0
	if n == 0 {
		n = 1
	}
	var last, x [16]byte
	if complete {
		copy(last[:], msg[(n-1)*16:])
		subtle.XORBytes(last[:], last[:], k1[:])
	} else {
		rest := msg[(n-1)*16:]
		copy(last[:], rest)
		last[len(rest)] = 0x80
		subtle.XORBytes(last[:], last[:], k2[:])
	}
	for i := 0; i < n-1; i++ {
		subtle.XORBytes(x[:], x[:], msg[i*16:(i+1)*16])
		blk.Encrypt(x[:], x[:])
	}
	subtle.XORBytes(x[:], x[:], last[:])
	blk.Encrypt(x[:], x[:])
	return x[:], nil
}
