// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gateway_test

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cB-Sigma/mqttsn"
	"github.com/cB-Sigma/mqttsn/client"
	"github.com/cB-Sigma/mqttsn/gateway"
)

// A gateway with an in-process broker, and a device publishing through it.
func Example() {
	b := gateway.NewMemoryBroker()
	got := make(chan gateway.Delivery, 1)
	b.Subscribe("sensors/#", func(d gateway.Delivery) { got <- d })
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = gateway.New(b, gateway.Options{}).Serve(ctx, pc) }()

	dev, _ := client.Dial(pc.LocalAddr().String(), "boiler")
	defer dev.Close()
	_ = dev.Connect(ctx, time.Minute, true, nil)
	id, _ := dev.Register(ctx, "sensors/boiler/temp")
	_ = dev.Publish(ctx, mqttsn.TopicNormal, id, 1, false, []byte("61.5"))
	d := <-got
	fmt.Println(d.Topic, string(d.Payload))
	// Output: sensors/boiler/temp 61.5
}
