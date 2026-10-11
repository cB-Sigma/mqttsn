// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/mqttsn"
	"github.com/cB-Sigma/mqttsn/client"
	"github.com/cB-Sigma/mqttsn/gateway"
)

type seen struct {
	mu sync.Mutex
	ds []gateway.Delivery
}

func (s *seen) add(d gateway.Delivery) { s.mu.Lock(); s.ds = append(s.ds, d); s.mu.Unlock() }
func (s *seen) wait(t *testing.T, topic, payload string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for _, d := range s.ds {
			if d.Topic == topic && string(d.Payload) == payload {
				s.mu.Unlock()
				return
			}
		}
		s.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("broker did not see %s=%s", topic, payload)
}

func start(t *testing.T, o gateway.Options) (*gateway.MemoryBroker, string, *seen) {
	t.Helper()
	b := gateway.NewMemoryBroker()
	s := &seen{}
	b.Subscribe("#", s.add)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = gateway.New(b, o).Serve(ctx, pc); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return b, pc.LocalAddr().String(), s
}

func recv(t *testing.T, c *client.Client, topic string) client.Delivery {
	t.Helper()
	select {
	case d := <-c.Messages():
		if d.Topic != topic {
			t.Fatalf("delivery on %q, want %q", d.Topic, topic)
		}
		return d
	case <-time.After(5 * time.Second):
		t.Fatalf("no delivery on %s", topic)
	}
	return client.Delivery{}
}

// The gateway relays a client's publishes at every QoS and topic form,
// delivers subscriptions with REGISTER, keeps messages for a sleeping
// client until it wakes, and publishes the will of a lost client.
// Covers: SIG-IPE-6720
func TestGatewayWithClient(t *testing.T) {
	b, addr, s := start(t, gateway.Options{Predefined: map[uint16]string{5: "pre/five"}, Retry: 300 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := client.Dial(addr, "dev1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Connect(ctx, 2*time.Second, true, &client.Will{Topic: "dev1/status", Msg: []byte("gone"), QoS: 1}); err != nil {
		t.Fatal(err)
	}
	id, err := c.Register(ctx, "dev1/temp")
	if err != nil {
		t.Fatal(err)
	}
	for q := int8(0); q <= 2; q++ {
		if err := c.Publish(ctx, mqttsn.TopicNormal, id, q, false, []byte{'0' + byte(q)}); err != nil {
			t.Fatalf("QoS %d: %v", q, err)
		}
		s.wait(t, "dev1/temp", string([]byte{'0' + byte(q)}))
	}
	sh, _ := mqttsn.ShortTopic("ab")
	_ = c.Publish(ctx, mqttsn.TopicShort, sh, 1, false, []byte("short"))
	s.wait(t, "ab", "short")
	_ = c.Publish(ctx, mqttsn.TopicPredefined, 5, 1, false, []byte("pre"))
	s.wait(t, "pre/five", "pre")

	if _, _, err := c.Subscribe(ctx, mqttsn.TopicNormal, "cmd/#", 0, 2); err != nil {
		t.Fatal(err)
	}
	_ = b.Publish(ctx, "cmd/dev1/set", []byte("on"), 2, false)
	if d := recv(t, c, "cmd/dev1/set"); string(d.Data) != "on" || d.QoS != 2 {
		t.Errorf("delivery %+v", d)
	}
	// Sleep: queued, then delivered on wake before PINGRESP.
	if err := c.Sleep(ctx, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	_ = b.Publish(ctx, "cmd/dev1/a", []byte("1"), 1, false)
	_ = b.Publish(ctx, "cmd/dev1/b", []byte("2"), 1, false)
	select {
	case d := <-c.Messages():
		t.Fatalf("delivered while asleep: %+v", d)
	case <-time.After(300 * time.Millisecond):
	}
	if err := c.Wake(ctx); err != nil {
		t.Fatal(err)
	}
	recv(t, c, "cmd/dev1/a")
	recv(t, c, "cmd/dev1/b")
	// Lost: no traffic past keep-alive + 50% → will.
	_ = c.Connect(ctx, 1*time.Second, false, &client.Will{Topic: "dev1/status", Msg: []byte("gone")})
	s.wait(t, "dev1/status", "gone")
}

// Wireless nodes behind a forwarder each get their own session; answers
// come back encapsulated for the node.
// Covers: SIG-IPE-6721
func TestGatewayForwarder(t *testing.T) {
	_, addr, s := start(t, gateway.Options{})
	gw, _ := net.ResolveUDPAddr("udp", addr)
	fwd, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer fwd.Close()
	_ = fwd.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	for _, node := range [][]byte{{0x01}, {0x02}} {
		con := (&mqttsn.Message{Type: mqttsn.CONNECT, Flags: mqttsn.Flags{CleanSession: true}, Duration: 30, ClientID: "node" + string('0'+node[0])}).Encode()
		_, _ = fwd.WriteToUDP(mqttsn.Encapsulate(1, node, con), gw)
		n, _, err := fwd.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		r, nd, inner, ok := mqttsn.Decapsulate(buf[:n])
		m, _ := mqttsn.Decode(inner)
		if !ok || r != 1 || string(nd) != string(node) || m == nil || m.Type != mqttsn.CONNACK {
			t.Fatalf("answer % x", buf[:n])
		}
		sh, _ := mqttsn.ShortTopic("n" + string('0'+node[0]))
		pub := (&mqttsn.Message{Type: mqttsn.PUBLISH, Flags: mqttsn.Flags{TopicIDType: mqttsn.TopicShort}, TopicID: sh, Data: []byte("x")}).Encode()
		_, _ = fwd.WriteToUDP(mqttsn.Encapsulate(1, node, pub), gw)
		s.wait(t, "n"+string('0'+node[0]), "x")
	}
}

// QoS -1 publishes from clients without a session reach the broker on
// predefined and short topics; SEARCHGW is answered with GWINFO.
// Covers: SIG-IPE-6720
func TestGatewayQoSMinus1AndSearch(t *testing.T) {
	_, addr, s := start(t, gateway.Options{GatewayID: 9, Predefined: map[uint16]string{7: "pre/seven"}})
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write((&mqttsn.Message{Type: mqttsn.PUBLISH, Flags: mqttsn.Flags{QoS: -1, TopicIDType: mqttsn.TopicPredefined}, TopicID: 7, Data: []byte("v")}).Encode())
	s.wait(t, "pre/seven", "v")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	id, _, err := client.SearchGW(ctx, addr, 1)
	if err != nil || id != 9 {
		t.Errorf("SEARCHGW: %d %v", id, err)
	}
}
