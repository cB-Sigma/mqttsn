# Changelog

## v0.2.0 (2026-10-12)

Added:

- `client`: MQTT-SN 1.2 (`Client`) and 2.0 (`Client2`) clients, on UDP or
  any datagram connection (`New`, `New2`), with `KeepAlive`, retry
  options and hooks (`Filter`, `Accept`, `AcceptRegister`). They were
  mqttsn-sim's; mqttsn-sim now wraps them.
- `gateway`: an MQTT-SN 1.2 gateway (search, advertise, connect with
  will and will updates, register both ways, publish QoS -1 to 2 on
  normal, predefined and short topics, subscribe with wildcards, sleeping
  clients, lost clients' wills, forwarded nodes) behind a `Broker`
  interface; `MemoryBroker` in process.
- `gateway/mqttbroker`: an MQTT 5 broker connection, transparent or
  aggregating (Eclipse Paho Go client).
- `forwarder` and `Encapsulate` / `Decapsulate`: the 1.2 forwarder role.
- `dtls`: MQTT-SN over DTLS 1.2 for client and gateway (Pion DTLS).
- Interop (nested module `interop`): the Paho MQTT-SN sample clients
  through this gateway to Mosquitto (transparent and aggregating);
  bisquitt 0.9.1's clients against this gateway and this client against
  bisquitt's gateway, over UDP and DTLS.

Dependencies added: github.com/eclipse/paho.golang v0.23.0,
github.com/pion/dtls/v3 v3.1.10.

## v0.1.0 (2026-10-11)

First published release: the MQTT-SN 1.2 codec, the MQTT-SN 2.0 (draft
CSD01) codec and the 2.0 Protection Encapsulation.

The UDP clients that were the `sim` package and `cmd/mqttsnsim` are in
the separate module mqttsn-sim. Requires iotcrypto v0.2.0.
