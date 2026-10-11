# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go from the specifications
below. No code was ported or copied from another MQTT-SN implementation
(Eclipse Paho MQTT-SN, the RSMB gateway, bisquitt and others were not
used as sources). The files came with SigmaM2M's baseline (2026-09-27),
where they sat in its MQTT-SN gateway, and became a module of their own
on 2026-10-06: `codec.go` (the 1.2 codec), `sn2/` (the 2.0 codec and the
Protection Encapsulation) and the clients. Two changes came with that
move: the Encapsulated Message type constant moved into codec.go from the
gateway's forwarder code, and the clients took the SCRAM implementation
of iotcrypto. The `Example` tests are new.

On 2026-10-11 the clients and their command moved to the separate module
mqttsn-sim (with `git mv`), so this module is the codecs only; the
interop tests against Eclipse Paho's gateway are in mqttsn-sim.

On 2026-10-11 and 12 (v0.2.0) the module took on the roles:

- `client`: the 1.2 and 2.0 clients came back from mqttsn-sim (where they
  had moved the day before), on any datagram connection, with option
  hooks in place of the simulator's fault switches, which stay in
  mqttsn-sim.
- `gateway`: the MQTT-SN 1.2 gateway of SigmaM2M (its session code and the 1.2
  parts of its MQTT-SN adapter), by the same author: the
  session code was copied and its SigmaM2M dependencies replaced by the
  `Broker` and `Link` interfaces, a warning callback and options;
  `MemoryBroker` is new. The 2.0 gateway stays in SigmaM2M.
- `gateway/mqttbroker`: the broker connection of SigmaM2M's gateway
  (upstream.go: transparent and aggregating modes), on Eclipse Paho's Go
  client as there.
- `forwarder` and the root's `Encapsulate` and `Decapsulate`: the
  encapsulation of SigmaM2M's forwarder.go, and a new UDP forwarder.
- `dtls`: new, on Pion DTLS.
- `interop/`: new, against the Paho MQTT-SN sample clients and bisquitt.

## Sources

| Area (files) | Followed |
|---|---|
| 1.2 codec (codec.go) | MQTT-SN Protocol Specification Version 1.2 (A. Stanford-Clark, H. L. Truong, IBM, 2013), clause 5 |
| 2.0 codec (sn2/codec.go) | OASIS MQTT-SN Version 2.0, Committee Specification Draft 01 (05 February 2026). A draft: clause numbers refer to it and may change |
| Gateway, forwarder, client (gateway/, forwarder/, forwarder.go, client/) | MQTT-SN 1.2 clauses 5.5 (forwarder encapsulation), 6 (gateway advertisement and discovery, connection set-up, will, registration, publish, subscribe, keep-alive, sleeping clients) and 7.2 (timers) |
| DTLS (dtls/) | none beyond Pion DTLS's API (DTLS 1.2, RFC 6347) |
| Interop peers (interop/) | the command lines of the Paho MQTT-SN sample clients and of bisquitt, read to drive them |
| Protection Encapsulation (sn2/protect.go) | the same draft, clause 3.17; AES-CMAC per RFC 4493 and NIST SP 800-38B; AES-CCM and AES-GCM per NIST SP 800-38C and 800-38D; ChaCha20-Poly1305 per RFC 8439 |

No specification text is reproduced; comments cite clause numbers in our
own words.

## Notes on open readings (F- numbers)

Where the 2.0 draft leaves a layout open, the choice made was recorded in
SigmaM2M's register of findings, and code comments cite its numbers. In
our words:

| Note | Where | Choice |
|---|---|---|
| F-2070 to F-2073 | Protection Encapsulation (sn2/protect.go) | the Length field covers the whole datagram including the tag; the AEAD schemes encrypt the protected packet with every byte before it as associated data, and the nonce is taken from a SHA-256 of those bytes; the draft does not state what the AEAD encrypts |

## Test vectors and where they come from

| Test | Source |
|---|---|
| codec_test.go, codec_clauses_test.go | messages worked from the clauses of MQTT-SN 1.2 that each test names |
| sn2/codec_test.go | packets worked from the clauses of the 2.0 draft that each test names |
| sn2/protect_test.go | RFC 4493 AES-CMAC vectors; the other schemes round-trip through their Go implementations |
| example_test.go, sn2/example_test.go, gateway/example_test.go | demo values |
| gateway/, forwarder/, dtls/ tests | the client and the gateway of this module against each other (same author, not independent) |
| interop/ | Paho MQTT-SN sample clients (e1e1b73) and bisquitt 0.9.1 as independent clients and gateway; Mosquitto as the broker |

Client IDs, topics, keys and passwords are made-up demo values.
