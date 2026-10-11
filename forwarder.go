// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mqttsn

// Forwarder encapsulation (MQTT-SN 1.2 clause 5.5): a forwarder relays the
// messages of wireless nodes that cannot reach the gateway themselves,
// each in an Encapsulated Message: the length of the encapsulation header,
// type 0xFE, a control octet whose two low bits are the broadcast radius,
// and the node's wireless node ID, followed by the MQTT-SN message. The
// gateway answers each node encapsulated the same way.

// Encapsulate wraps msg for (or from) the wireless node with ID node.
func Encapsulate(radius byte, node, msg []byte) []byte {
	h := make([]byte, 0, 3+len(node)+len(msg))
	h = append(h, byte(3+len(node)), byte(Encapsulated), radius&0x03)
	h = append(h, node...)
	return append(h, msg...)
}

// Decapsulate unwraps an Encapsulated Message; ok is false for any other
// datagram or a malformed encapsulation (no node ID, a header longer than
// the datagram).
func Decapsulate(b []byte) (radius byte, node, msg []byte, ok bool) {
	if len(b) < 3 || MsgType(b[1]) != Encapsulated {
		return 0, nil, nil, false
	}
	l := int(b[0])
	if l < 4 || l > len(b) {
		return 0, nil, nil, false
	}
	return b[2] & 0x03, append([]byte(nil), b[3:l]...), b[l:], true
}
