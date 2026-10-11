// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package forwarder_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/cB-Sigma/mqttsn"
	"github.com/cB-Sigma/mqttsn/client"
	"github.com/cB-Sigma/mqttsn/forwarder"
	"github.com/cB-Sigma/mqttsn/gateway"
)

// Two clients reach the gateway only through the forwarder: each has its
// own session at the gateway, publishes and receives its subscription;
// encapsulation round-trips.
// Covers: SIG-IPE-6721
func TestForwarder(t *testing.T) {
	enc := mqttsn.Encapsulate(2, []byte{1, 2}, []byte{3, 0x18, 0})
	if r, n, m, ok := mqttsn.Decapsulate(enc); !ok || r != 2 || !bytes.Equal(n, []byte{1, 2}) || !bytes.Equal(m, []byte{3, 0x18, 0}) {
		t.Fatalf("decapsulate % x", enc)
	}
	if _, _, _, ok := mqttsn.Decapsulate([]byte{3, 0xFE, 0}); ok {
		t.Error("an encapsulation without a node ID was accepted")
	}
	b := gateway.NewMemoryBroker()
	got := make(chan gateway.Delivery, 8)
	b.Subscribe("dev/#", func(d gateway.Delivery) { got <- d })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	gpc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	g := gateway.New(b, gateway.Options{})
	go func() { _ = g.Serve(ctx, gpc) }()
	npc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	f, err := forwarder.New(npc, gpc.LocalAddr().String(), forwarder.Options{Radius: 1})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = f.Run(ctx) }()
	for _, id := range []string{"n1", "n2"} {
		c, err := client.Dial(npc.LocalAddr().String(), id)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := c.Connect(ctx, 30*time.Second, true, nil); err != nil {
			t.Fatal(err)
		}
		tid, err := c.Register(ctx, "dev/"+id)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Publish(ctx, mqttsn.TopicNormal, tid, 1, false, []byte(id)); err != nil {
			t.Fatal(err)
		}
		select {
		case d := <-got:
			if d.Topic != "dev/"+id {
				t.Errorf("got %+v", d)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no publish through the forwarder")
		}
	}
	if cl := g.Clients(); len(cl) != 2 {
		t.Errorf("gateway sessions %v", cl)
	}
	if f.Relayed() < 8 {
		t.Errorf("relayed %d", f.Relayed())
	}
}
