# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# bisquitt v0.9.1 (EPL-2.0, github.com/energostack/bisquitt), an MQTT-SN 1.2
# gateway and client in Go with DTLS, built from source, next to
# Mosquitto from Alpine, as an independent peer for the interop tests.
#
#   docker build -t sigma-mqttsn-bisquitt:0.9.1 .

FROM golang:1.24-alpine AS build
RUN apk add --no-cache git \
 && git clone --depth 1 --branch v0.9.1 https://github.com/energostack/bisquitt /src \
 && cd /src && CGO_ENABLED=0 go build -o /out/ ./cmd/bisquitt ./cmd/bisquitt-pub ./cmd/bisquitt-sub

FROM alpine:3.20
RUN apk add --no-cache mosquitto mosquitto-clients
COPY --from=build /out/ /usr/local/bin/
COPY start.sh /start.sh
RUN chmod 0755 /start.sh
ENTRYPOINT ["/start.sh"]
