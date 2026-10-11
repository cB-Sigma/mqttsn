// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	sn "github.com/cB-Sigma/mqttsn"
)

// Short names for the MQTT-SN v1.2 codec of the module root, so the
// gateway reads as the protocol does.

type (
	MsgType    = sn.MsgType
	ReturnCode = sn.ReturnCode
	Flags      = sn.Flags
	Message    = sn.Message
)

// Message types.
const (
	ADVERTISE     = sn.ADVERTISE
	SEARCHGW      = sn.SEARCHGW
	GWINFO        = sn.GWINFO
	CONNECT       = sn.CONNECT
	CONNACK       = sn.CONNACK
	WILLTOPICREQ  = sn.WILLTOPICREQ
	WILLTOPIC     = sn.WILLTOPIC
	WILLMSGREQ    = sn.WILLMSGREQ
	WILLMSG       = sn.WILLMSG
	REGISTER      = sn.REGISTER
	REGACK        = sn.REGACK
	PUBLISH       = sn.PUBLISH
	PUBACK        = sn.PUBACK
	PUBCOMP       = sn.PUBCOMP
	PUBREC        = sn.PUBREC
	PUBREL        = sn.PUBREL
	SUBSCRIBE     = sn.SUBSCRIBE
	SUBACK        = sn.SUBACK
	UNSUBSCRIBE   = sn.UNSUBSCRIBE
	UNSUBACK      = sn.UNSUBACK
	PINGREQ       = sn.PINGREQ
	PINGRESP      = sn.PINGRESP
	DISCONNECT    = sn.DISCONNECT
	WILLTOPICUPD  = sn.WILLTOPICUPD
	WILLTOPICRESP = sn.WILLTOPICRESP
	WILLMSGUPD    = sn.WILLMSGUPD
	WILLMSGRESP   = sn.WILLMSGRESP

	// Encapsulated is the forwarder's Encapsulated Message.
	Encapsulated = sn.Encapsulated
)

// Return codes, topic ID types and limits.
const (
	Accepted          = sn.Accepted
	RejectedCongested = sn.RejectedCongested
	RejectedTopicID   = sn.RejectedTopicID
	RejectedNotSupp   = sn.RejectedNotSupp

	TopicNormal     = sn.TopicNormal
	TopicPredefined = sn.TopicPredefined
	TopicShort      = sn.TopicShort
	TopicReserved   = sn.TopicReserved

	MaxLength  = sn.MaxLength
	ProtocolID = sn.ProtocolID
)

// ErrShort is returned for a message shorter than its header says.
var ErrShort = sn.ErrShort

// ParseFlags decodes a flags byte.
func ParseFlags(b byte) Flags { return sn.ParseFlags(b) }

// Decode decodes one MQTT-SN v1.2 message.
func Decode(b []byte) (*Message, error) { return sn.Decode(b) }

// ShortTopic returns the topic ID of a two-character topic name.
func ShortTopic(name string) (uint16, bool) { return sn.ShortTopic(name) }

// ShortName is the two-character name of a short topic ID.
func ShortName(id uint16) string { return sn.ShortName(id) }
