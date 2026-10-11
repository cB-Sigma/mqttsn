// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package dtls carries MQTT-SN over DTLS 1.2 (Pion's pure-Go DTLS,
// github.com/pion/dtls/v3) for the client and gateway of this module:
// Dial gives a client its connection, Listen gives the gateway a
// net.PacketConn whose peers are DTLS sessions.
package dtls

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	pdtls "github.com/pion/dtls/v3"
)

// Config is Pion's DTLS configuration (certificates or pre-shared keys).
type Config = pdtls.Config

// Dial opens a DTLS session to the gateway at addr and completes the
// handshake; pass the result to client.New or client.New2.
func Dial(ctx context.Context, addr string, cfg *Config) (net.Conn, error) {
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := pdtls.Dial("udp", ra, cfg)
	if err != nil {
		return nil, err
	}
	if err := c.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// PacketConn is the gateway side: every DTLS session accepted on the
// listener is a peer, addressed by its UDP address.
type PacketConn struct {
	ln    net.Listener
	in    chan packet
	mu    sync.Mutex
	conns map[string]net.Conn
	done  chan struct{}
	once  sync.Once
	// OnError receives handshake failures (optional).
	OnError func(error)
}

type packet struct {
	b    []byte
	from net.Addr
}

// Listen accepts DTLS sessions on the UDP address addr.
func Listen(addr string, cfg *Config) (*PacketConn, error) {
	la, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	ln, err := pdtls.Listen("udp", la, cfg)
	if err != nil {
		return nil, err
	}
	p := &PacketConn{ln: ln, in: make(chan packet, 256), conns: map[string]net.Conn{}, done: make(chan struct{})}
	go p.accept()
	return p, nil
}

func (p *PacketConn) accept() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
			}
			if p.OnError != nil {
				p.OnError(err)
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go p.serve(c)
	}
}

func (p *PacketConn) serve(c net.Conn) {
	if dc, ok := c.(*pdtls.Conn); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := dc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			if p.OnError != nil {
				p.OnError(err)
			}
			_ = c.Close()
			return
		}
	}
	key := c.RemoteAddr().String()
	p.mu.Lock()
	if old := p.conns[key]; old != nil {
		_ = old.Close()
	}
	p.conns[key] = c
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if p.conns[key] == c {
			delete(p.conns, key)
		}
		p.mu.Unlock()
		_ = c.Close()
	}()
	buf := make([]byte, 65536)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		select {
		case p.in <- packet{append([]byte(nil), buf[:n]...), c.RemoteAddr()}:
		case <-p.done:
			return
		}
	}
}

// ReadFrom returns the next datagram of any session.
func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case pk := <-p.in:
		return copy(b, pk.b), pk.from, nil
	case <-p.done:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo sends b to the session with address addr.
func (p *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.mu.Lock()
	c := p.conns[addr.String()]
	p.mu.Unlock()
	if c == nil {
		return 0, errors.New("dtls: no session with " + addr.String())
	}
	return c.Write(b)
}

// Close closes the listener and every session.
func (p *PacketConn) Close() error {
	p.once.Do(func() { close(p.done) })
	err := p.ln.Close()
	p.mu.Lock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
	return err
}

// LocalAddr is the listener's address.
func (p *PacketConn) LocalAddr() net.Addr { return p.ln.Addr() }

// SetDeadline, SetReadDeadline and SetWriteDeadline are not supported
// (they return nil and do nothing); close the PacketConn to stop reads.
func (p *PacketConn) SetDeadline(time.Time) error      { return nil }
func (p *PacketConn) SetReadDeadline(time.Time) error  { return nil }
func (p *PacketConn) SetWriteDeadline(time.Time) error { return nil }
