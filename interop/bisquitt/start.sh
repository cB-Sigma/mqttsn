#!/bin/sh
# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# "gateway [flags]" starts Mosquitto on 127.0.0.1:1883 and the bisquitt
# gateway on UDP 1884 with the flags given (--dtls --self-signed, say);
# anything else is run as a command (bisquitt-pub, bisquitt-sub).
set -e
if [ "$1" = "gateway" ]; then
	shift
	mosquitto -p 1883 -d
	sleep 0.5
	echo "PEER READY"
	exec bisquitt --host 0.0.0.0 --port 1884 "$@"
fi
exec "$@"
