// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mqttsn_test

import (
	"fmt"

	"github.com/cB-Sigma/mqttsn"
)

// A QoS 1 PUBLISH on a registered topic ID, encoded and decoded again.
func Example() {
	m := &mqttsn.Message{Type: mqttsn.PUBLISH, Flags: mqttsn.Flags{QoS: 1, TopicIDType: mqttsn.TopicNormal},
		TopicID: 7, MsgID: 1, Data: []byte("21.5")}
	b := m.Encode()
	fmt.Printf("% X\n", b)
	d, err := mqttsn.Decode(b)
	fmt.Println(d.Type, d.Flags.QoS, d.TopicID, string(d.Data), err)
	// Output:
	// 0B 0C 20 00 07 00 01 32 31 2E 35
	// PUBLISH 1 7 21.5 <nil>
}

// A two-character topic name travels in the topic ID field.
func ExampleShortTopic() {
	id, ok := mqttsn.ShortTopic("t1")
	fmt.Printf("%#04x %v %s\n", id, ok, mqttsn.ShortName(id))
	// Output: 0x7431 true t1
}
