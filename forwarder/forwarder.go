// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package forwarder is an MQTT-SN 1.2 forwarder (clause 5.5): it relays
// the messages of nodes that cannot reach the gateway themselves,
// wrapping each in an Encapsulated Message with the node's wireless node
// ID, and passes the gateway's answers back to the node they name. Nodes
// reach it over any net.PacketConn (UDP here; a radio driver can offer the
// same interface); a node's ID is derived from its address.
package forwarder

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/cB-Sigma/mqttsn"
)

// Forwarder relays between nodes and one gateway.
type Forwarder struct {
	nodes   net.PacketConn
	gw      net.Conn
	radius  byte
	mu      sync.Mutex
	byID    map[string]net.Addr
	relayed int
}

// Options configure a forwarder.
type Options struct {
	// Radius is the broadcast radius put in the control octet (0 to 3).
	Radius byte
}

// New relays between the node-side connection and the gateway at addr.
func New(nodes net.PacketConn, gatewayAddr string, o Options) (*Forwarder, error) {
	gw, err := net.Dial("udp", gatewayAddr)
	if err != nil {
		return nil, err
	}
	return &Forwarder{nodes: nodes, gw: gw, radius: o.Radius & 3, byID: map[string]net.Addr{}}, nil
}

// NodeID is the wireless node ID the forwarder gives a node address: the
// IPv4 or IPv6 address and the port, or the address text for other
// networks.
func NodeID(a net.Addr) []byte {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		ip := ap.Addr().Unmap()
		return binary.BigEndian.AppendUint16(ip.AsSlice(), ap.Port())
	}
	return []byte(a.String())
}

// Relayed counts the datagrams relayed in both directions.
func (f *Forwarder) Relayed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.relayed
}

// Run relays until ctx ends; it then closes both connections.
func (f *Forwarder) Run(ctx context.Context) error {
	go func() { <-ctx.Done(); _ = f.nodes.Close(); _ = f.gw.Close() }()
	errc := make(chan error, 2)
	go func() { errc <- f.up() }()
	go func() { errc <- f.down() }()
	err := <-errc
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (f *Forwarder) up() error {
	buf := make([]byte, 65536)
	for {
		n, from, err := f.nodes.ReadFrom(buf)
		if err != nil {
			return err
		}
		id := NodeID(from)
		f.mu.Lock()
		f.byID[string(id)] = from
		f.relayed++
		f.mu.Unlock()
		_, _ = f.gw.Write(mqttsn.Encapsulate(f.radius, id, buf[:n]))
	}
}

func (f *Forwarder) down() error {
	buf := make([]byte, 65536)
	for {
		n, err := f.gw.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && !errors.Is(err, net.ErrClosed) {
				continue // an ICMP error before the gateway listens
			}
			return err
		}
		_, node, msg, ok := mqttsn.Decapsulate(buf[:n])
		if !ok {
			continue // the gateway's own broadcasts (ADVERTISE) are not relayed
		}
		f.mu.Lock()
		to := f.byID[string(node)]
		f.relayed++
		f.mu.Unlock()
		if to != nil {
			_, _ = f.nodes.WriteTo(msg, to)
		}
	}
}
