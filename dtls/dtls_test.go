// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dtls_test

import (
	"context"
	"testing"
	"time"

	pdtls "github.com/pion/dtls/v3"

	"github.com/cB-Sigma/mqttsn"
	"github.com/cB-Sigma/mqttsn/client"
	"github.com/cB-Sigma/mqttsn/dtls"
	"github.com/cB-Sigma/mqttsn/gateway"
)

func pskConfig(id string) *dtls.Config {
	return &dtls.Config{
		PSK:             func([]byte) ([]byte, error) { return []byte("demo-psk-secret"), nil },
		PSKIdentityHint: []byte(id),
		CipherSuites:    []pdtls.CipherSuiteID{pdtls.TLS_PSK_WITH_AES_128_GCM_SHA256},
	}
}

// A client connects, publishes and receives a subscription over DTLS 1.2
// (pre-shared key) to the gateway; a client with the wrong key gets no
// session.
// Covers: SIG-IPE-6723
func TestGatewayOverDTLS(t *testing.T) {
	pc, err := dtls.Listen("127.0.0.1:0", pskConfig("gateway"))
	if err != nil {
		t.Fatal(err)
	}
	b := gateway.NewMemoryBroker()
	got := make(chan gateway.Delivery, 8)
	b.Subscribe("dev/#", func(d gateway.Delivery) { got <- d })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = gateway.New(b, gateway.Options{}).Serve(ctx, pc); close(done) }()
	defer func() { cancel(); <-done }()

	conn, err := dtls.Dial(ctx, pc.LocalAddr().String(), pskConfig("dev1"))
	if err != nil {
		t.Fatal(err)
	}
	c := client.New(conn, "dev1", client.Options{})
	defer c.Close()
	if err := c.Connect(ctx, 30*time.Second, true, nil); err != nil {
		t.Fatal(err)
	}
	id, err := c.Register(ctx, "dev/temp")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Publish(ctx, mqttsn.TopicNormal, id, 1, false, []byte("21.5")); err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-got:
		if d.Topic != "dev/temp" || string(d.Payload) != "21.5" {
			t.Errorf("broker got %+v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reached the broker")
	}
	if _, _, err := c.Subscribe(ctx, mqttsn.TopicNormal, "cmd/dev1", 0, 1); err != nil {
		t.Fatal(err)
	}
	_ = b.Publish(ctx, "cmd/dev1", []byte("on"), 1, false)
	select {
	case d := <-c.Messages():
		if string(d.Data) != "on" {
			t.Errorf("client got %+v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery over DTLS")
	}

	bad := pskConfig("dev2")
	bad.PSK = func([]byte) ([]byte, error) { return []byte("wrong"), nil }
	hctx, hcancel := context.WithTimeout(ctx, 3*time.Second)
	defer hcancel()
	if c2, err := dtls.Dial(hctx, pc.LocalAddr().String(), bad); err == nil {
		_ = c2.Close()
		t.Error("a client with the wrong key completed the handshake")
	}
}
