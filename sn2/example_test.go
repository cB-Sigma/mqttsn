// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sn2_test

import (
	"fmt"

	"github.com/cB-Sigma/mqttsn/sn2"
)

// A REGISTER for a topic name, encoded and decoded again.
func Example() {
	p := &sn2.Packet{Type: sn2.REGISTER, PacketID: 1, TopicName: "sensors/t"}
	d, err := sn2.Decode(p.Encode())
	fmt.Println(d.Type, d.PacketID, d.TopicName, err)
	// Output: REGISTER 1 sensors/t <nil>
}
