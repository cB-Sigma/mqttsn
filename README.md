# mqttsn

MQTT-SN 1.2 and 2.0 (draft) packet codecs in pure Go, with the 2.0 Protection Encapsulation.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/mqttsn.svg)](https://pkg.go.dev/github.com/cB-Sigma/mqttsn) [![test](https://github.com/cB-Sigma/mqttsn/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/mqttsn/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.26.0-00ADD8.svg)](go.mod)

The module encodes and decodes every MQTT-SN 1.2 message, and every
packet, property and envelope of the OASIS MQTT-SN 2.0 Committee
Specification Draft 01, including the Protection Encapsulation (HMAC,
CMAC, AES-CCM, AES-GCM, ChaCha20-Poly1305). It lays packets out only;
the behaviour of a client or a gateway is the application's. It was
written for SigmaM2M, a oneM2M platform, whose MQTT-SN gateway it
serves; the gateway itself is not part of this module. UDP clients of
both versions, usable as device simulators, are in
[mqttsn-sim](https://github.com/cB-Sigma/mqttsn-sim). It is built on the
standard library, golang.org/x/crypto and
[iotcrypto](https://github.com/cB-Sigma/iotcrypto), without cgo.

## Features

| Feature | Status |
|---|---|
| MQTT-SN 1.2, every message type of clause 5.2.2: decode and encode | yes |
| 1.2 flags, return codes, topic ID types (normal, predefined, short), short topic names | yes |
| Forwarder encapsulation (1.2 clause 5.5) | the type constant; unwrapping is the gateway's |
| MQTT-SN 2.0 draft CSD01: packets, reason codes, properties, envelopes | yes; the draft may still change |
| 2.0 Protection Encapsulation | HMAC, CMAC, AES-CCM, AES-GCM, ChaCha20-Poly1305; provider-defined schemes no |
| Client | in mqttsn-sim (1.2 and 2.0, UDP) |
| Gateway, broker connection | no |

## Choosing an MQTT-SN library

Compared from each project's source at the versions named, in October
2026. "Tested" means run against this module's codec through the
interop tests named below. Check the projects themselves before relying
on a row.

| | this module (with mqttsn-sim) | bisquitt v0.9.1 | Eclipse Paho MQTT-SN embedded-c (commit e1e1b73) | simon622/mqtt-sn (Java, commit bbc0246) |
|---|---|---|---|---|
| Language | Go, no cgo | Go | C (packet library, client) and C++ (gateway) | Java |
| Licence | Apache-2.0 | EPL-2.0 | EPL-2.0 / EDL-1.0 | Apache-2.0 |
| What it is | codecs; clients in mqttsn-sim | a transparent gateway and a client | packet library, sample clients, a gateway | gateway and client |
| MQTT-SN 1.2 | yes (tested with Paho's gateway and clients) | yes | yes | yes |
| MQTT-SN 2.0 | draft CSD01 (2026), not tested against another implementation | AUTH only, from an earlier working draft; 2.0 planned | no | an earlier working draft that keeps the 1.2 packet numbers (CONNECT 0x04; CSD01 0x01), so not wire-compatible with CSD01 |
| 2.0 Protection Encapsulation | yes | no | no | a protection module for its earlier draft |
| DTLS | no | yes (DTLS 1.2) | yes (gateway, DTLS build) | not checked |
| Gateway | no (SigmaM2M's is not published) | yes | yes | yes |

Pick this module to read or write MQTT-SN 2.0 packets in Go, or for a
codec under a gateway or client of your own. Pick bisquitt for a ready
MQTT-SN 1.2 gateway in Go, with DTLS; pick Paho's gateway or client for
C and C++ devices and a widely used gateway. This module has no gateway
and no DTLS.

## Install

```
go get github.com/cB-Sigma/mqttsn@latest
```

Requires Go 1.26.0 or later.

## Quick start

```go
import "github.com/cB-Sigma/mqttsn"

m := &mqttsn.Message{Type: mqttsn.PUBLISH, Flags: mqttsn.Flags{QoS: 1},
	TopicID: 7, MsgID: 1, Data: []byte("21.5")}
b := m.Encode()           // 0B 0C 20 00 07 00 01 32 31 2E 35
d, err := mqttsn.Decode(b)
```

The runnable examples are the `Example` tests of the module root and of
`sn2`.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/mqttsn

| Package | What it does |
|---|---|
| `mqttsn` (module root) | MQTT-SN 1.2 messages: `Message`, `Decode`, `Encode`, `Flags`, return codes, topic ID types, `ShortTopic`, `ShortName`, the forwarder's `Encapsulated` type |
| `sn2` | MQTT-SN 2.0 (draft CSD01) packets: `Packet`, `Decode`, `Encode`, reason codes, properties, the envelopes; the Protection Encapsulation |

## Testing

```
go vet ./...
go test -race ./...
```

Tests carry `// Covers: SIG-...` comments: these are requirement IDs of
the SigmaM2M project's compliance report and have no meaning outside it.
Code comments that cite `F-` numbers refer to SigmaM2M's register of
readings where the 2.0 draft leaves a choice open; PROVENANCE.md
explains them.

### Interop tested against

On 2026-10-11, Docker Desktop 29.4.3 on arm64:

- Eclipse Paho MQTT-SN gateway (paho.mqtt-sn.embedded-c at commit
  e1e1b73, gateway version 1.5.1) in front of Mosquitto 2.0 from Debian
  bookworm: the 1.2 client of mqttsn-sim, built on this codec, connected,
  registered, published at QoS 0, 1 and 2, on a short topic name, on a
  predefined topic ID and retained, subscribed with a wildcard, a short
  topic name and a predefined topic ID, received what the broker sent
  (with the gateway's REGISTER), unsubscribed, pinged, disconnected, and
  slept and woke up for stored messages. The tests are in mqttsn-sim's
  `interop` module. Two Paho defects were seen: it discards WILLTOPIC
  during the connect exchange (so no will can be set through it), and it
  sends no PINGRESP after delivering stored messages unless it had to
  register a topic first.
- The Paho MQTTSNPacket sample clients (qos-1pub, qos0pub, qos1pub,
  qos0pub_register, pub0sub1) against SigmaM2M's gateway, which uses this
  codec: all published to the broker, and pub0sub1's QoS 2 subscription
  got its own publish back. That test lives in SigmaM2M.
- MQTT-SN 2.0: no other implementation of draft CSD01 was found. Paho
  implements 1.2 only; bisquitt implements only AUTH from an earlier 2.0
  working draft; simon622/mqtt-sn follows an earlier working draft that
  keeps the 1.2 packet type numbers, so it cannot talk to CSD01. The
  2.0 codec and the Protection Encapsulation are tested against
  SigmaM2M's gateway and mqttsn-sim's client, by the same author: not
  independent. The CMAC vectors are RFC 4493's.
- Not yet: bisquitt, DTLS, gateway search (Paho answers SEARCHGW by
  multicast, which a container's port mapping does not carry).

## Related repositories

- [mqttsn-sim](https://github.com/cB-Sigma/mqttsn-sim): MQTT-SN 1.2 and
  2.0 clients over UDP, as a Go package and a simulated sensor command.
- [iotcrypto](https://github.com/cB-Sigma/iotcrypto): AES-CCM for the
  Protection Encapsulation.

## Status

v0.x: the API may change before v1. MQTT-SN 2.0 follows a draft.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.
