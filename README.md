# mqttsn

MQTT-SN 1.2 and 2.0 (draft) in pure Go: codecs with the 2.0 Protection Encapsulation, clients, a 1.2 gateway, a forwarder and DTLS.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/mqttsn.svg)](https://pkg.go.dev/github.com/cB-Sigma/mqttsn) [![test](https://github.com/cB-Sigma/mqttsn/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/mqttsn/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.26.0-00ADD8.svg)](go.mod)

The module encodes and decodes every MQTT-SN 1.2 message, and every
packet, property and envelope of the OASIS MQTT-SN 2.0 Committee
Specification Draft 01, including the Protection Encapsulation (HMAC,
CMAC, AES-CCM, AES-GCM, ChaCha20-Poly1305). On top of the codecs it has
clients of both versions, an MQTT-SN 1.2 gateway that relays to an MQTT
broker (in process, or an MQTT 5 broker in transparent or aggregating
mode), a forwarder, and DTLS 1.2 for client and gateway. It was written
for SigmaM2M, a oneM2M platform, whose MQTT-SN gateway it serves; the
1.2 gateway here was extracted from it. It is built on the standard
library, golang.org/x/crypto, [iotcrypto](https://github.com/cB-Sigma/iotcrypto),
Eclipse Paho's Go MQTT client (for `gateway/mqttbroker`) and Pion DTLS
(for `dtls`), without cgo.

## Features

| Feature | Status |
|---|---|
| MQTT-SN 1.2, every message type of clause 5.2.2: decode and encode | yes |
| 1.2 flags, return codes, topic ID types (normal, predefined, short), short topic names | yes |
| Forwarder encapsulation (1.2 clause 5.5) | yes: `Encapsulate`, `Decapsulate`, and a UDP forwarder (`forwarder`, v0.2.0) |
| MQTT-SN 2.0 draft CSD01: packets, reason codes, properties, envelopes | yes; the draft may still change |
| 2.0 Protection Encapsulation | HMAC, CMAC, AES-CCM, AES-GCM, ChaCha20-Poly1305; provider-defined schemes no |
| Client, 1.2 and 2.0 | yes (`client`, v0.2.0): search, connect with will, register, publish QoS -1 to 2, subscribe, sleep and wake, keep-alive; 2.0 also SCRAM and protection |
| Gateway, 1.2 | yes (`gateway`, v0.2.0): search and advertise, will and will updates, register both ways, publish QoS -1 to 2, subscribe with wildcards, sleeping clients, lost clients' wills, forwarded nodes; `MemoryBroker` or `gateway/mqttbroker` (MQTT 5, transparent or aggregating) |
| Gateway, 2.0 | no: SigmaM2M's 2.0 gateway is not extracted yet |
| DTLS | yes (`dtls`, v0.2.0): DTLS 1.2 with certificates or pre-shared keys, client and gateway |

## Choosing an MQTT-SN library

Compared from each project's source at the versions named, in October
2026. "Tested" means run against this module through the interop tests
named below. Check the projects themselves before relying on a row.

| | this module | bisquitt v0.9.1 | Eclipse Paho MQTT-SN embedded-c (commit e1e1b73) | simon622/mqtt-sn (Java, commit bbc0246) |
|---|---|---|---|---|
| Language | Go, no cgo | Go | C (packet library, client) and C++ (gateway) | Java |
| Licence | Apache-2.0 | EPL-2.0 | EPL-2.0 / EDL-1.0 | Apache-2.0 |
| What it is | codecs, clients, 1.2 gateway, forwarder | a transparent gateway and a client | packet library, sample clients, a gateway | gateway and client |
| MQTT-SN 1.2 | yes (tested with Paho's gateway and clients and with bisquitt's gateway and clients) | yes | yes | yes |
| MQTT-SN 2.0 | draft CSD01 (2026) codec and client, not tested against another implementation | AUTH only, from an earlier working draft; 2.0 planned | no | an earlier working draft that keeps the 1.2 packet numbers (CONNECT 0x04; CSD01 0x01), so not wire-compatible with CSD01 |
| 2.0 Protection Encapsulation | yes | no | no | a protection module for its earlier draft |
| DTLS | yes, DTLS 1.2 (tested with bisquitt both ways) | yes (DTLS 1.2) | yes (gateway, DTLS build) | not checked |
| Gateway | 1.2, transparent or aggregating (tested with Paho's clients and bisquitt's) | 1.2, transparent | 1.2, transparent or aggregating | yes |
| Forwarder | yes | no | the gateway accepts forwarders | not checked |

Pick this module for MQTT-SN in Go: a device client of either version,
a 1.2 gateway in front of any MQTT 5 broker or in process, a forwarder,
or a codec under your own gateway. Pick bisquitt for a ready 1.2 gateway
binary in Go with a PSK API; pick Paho's gateway or client for C and C++
devices and a widely deployed gateway. For an MQTT-SN 2.0 gateway there
is no published choice yet (SigmaM2M has one, not extracted).

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

A gateway with an in-process broker and a device (from the gateway's
`Example`):

```go
b := gateway.NewMemoryBroker()
b.Subscribe("sensors/#", func(d gateway.Delivery) { /* ... */ })
go gateway.New(b, gateway.Options{}).Serve(ctx, pc) // pc: a UDP net.PacketConn

dev, _ := client.Dial(addr, "boiler")
_ = dev.Connect(ctx, time.Minute, true, nil)
id, _ := dev.Register(ctx, "sensors/boiler/temp")
_ = dev.Publish(ctx, mqttsn.TopicNormal, id, 1, false, []byte("61.5"))
```

For an MQTT broker, `mqttbroker.Dial(ctx, mqttbroker.Options{URL:
"mqtt://127.0.0.1:1883"})` gives the `Broker`; for DTLS, serve on
`dtls.Listen(addr, cfg)` and give clients `dtls.Dial(ctx, addr, cfg)`.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/mqttsn

| Package | What it does |
|---|---|
| `mqttsn` (module root) | MQTT-SN 1.2 messages: `Message`, `Decode`, `Encode`, `Flags`, return codes, topic ID types, `ShortTopic`, `ShortName`; forwarder `Encapsulate`, `Decapsulate` |
| `sn2` | MQTT-SN 2.0 (draft CSD01) packets: `Packet`, `Decode`, `Encode`, reason codes, properties, the envelopes; the Protection Encapsulation |
| `client` | `Client` (1.2) and `Client2` (2.0) over UDP or any datagram connection; `SearchGW`, `SearchGW2` |
| `gateway` | the MQTT-SN 1.2 gateway: `New`, `Serve`, `Broker`, `Link`, `MemoryBroker`, `TopicMatch` |
| `gateway/mqttbroker` | `Broker` on an MQTT 5 broker, transparent or aggregating |
| `forwarder` | a UDP forwarder for nodes that cannot reach the gateway |
| `dtls` | `Dial` and `Listen` for MQTT-SN over DTLS 1.2 |
| `interop` (nested module, tests only) | this module against Paho and bisquitt in Docker |

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

`interop/` is a nested module with its own go.mod. It builds the Paho
MQTT-SN sample clients and Mosquitto (`interop/peer`) and bisquitt
(`interop/bisquitt`) in containers, and is skipped unless
`SIGMA_MQTTSN_INTEROP=1` is set and Docker is running:

```
cd interop && SIGMA_MQTTSN_INTEROP=1 go test -v ./...
```

### Interop tested against

On 2026-10-12, Docker Desktop 29.4.3 on arm64 (v0.2.0):

- The Paho MQTTSNPacket sample clients (qos-1pub, qos0pub, qos1pub,
  qos0pub_register, pub0sub1) against this module's gateway, relaying
  through `gateway/mqttbroker` to Mosquitto 2.0, in transparent and in
  aggregating mode: every sample published to the broker, the registered
  topic arrived, and pub0sub1's QoS 2 subscription got its own publish
  back. All passed.
- bisquitt 0.9.1: bisquitt-pub (QoS 0 and 1) and bisquitt-sub against
  this gateway, and this module's client against bisquitt's gateway
  (register, QoS 1 and 2 publishes, a subscription), each over UDP and
  over DTLS 1.2 with self-signed certificates. All passed.

On 2026-10-11 (v0.1.0, still run by mqttsn-sim's `interop` module, now
on this module's client):

- Eclipse Paho MQTT-SN gateway (paho.mqtt-sn.embedded-c at commit
  e1e1b73, gateway version 1.5.1) in front of Mosquitto 2.0 from Debian
  bookworm: the 1.2 client connected, registered, published at QoS 0, 1
  and 2, on a short topic name, on a predefined topic ID and retained,
  subscribed with a wildcard, a short topic name and a predefined topic
  ID, received what the broker sent (with the gateway's REGISTER),
  unsubscribed, pinged, disconnected, and slept and woke up for stored
  messages. Two Paho defects were seen: it discards WILLTOPIC during the
  connect exchange (so no will can be set through it), and it sends no
  PINGRESP after delivering stored messages unless it had to register a
  topic first.
- MQTT-SN 2.0: no other implementation of draft CSD01 was found. Paho
  implements 1.2 only; bisquitt implements only AUTH from an earlier 2.0
  working draft; simon622/mqtt-sn follows an earlier working draft that
  keeps the 1.2 packet type numbers, so it cannot talk to CSD01. The
  2.0 codec, client and the Protection Encapsulation are tested against
  SigmaM2M's gateway, by the same author: not independent. The CMAC
  vectors are RFC 4493's.
- Not yet: the forwarder against another gateway (it is tested against
  this module's gateway only), gateway search against Paho (Paho answers
  SEARCHGW by multicast, which a container's port mapping does not
  carry), DTLS with pre-shared keys against another implementation
  (bisquitt takes its keys from an HTTP API).

## Related repositories

- [mqttsn-sim](https://github.com/cB-Sigma/mqttsn-sim): this module's
  clients with fault switches (silence, congestion, refused REGISTER),
  and a simulated sensor command.
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
