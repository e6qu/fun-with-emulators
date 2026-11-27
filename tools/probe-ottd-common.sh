#!/bin/sh
# Probe: fetch OpenTTD 15.3 with its base sets into $1 (an Alpine root's /root).
set -eu
cd "$1"
curl -fsSLO https://cdn.openttd.org/openttd-releases/15.3/openttd-15.3-windows-arm64.zip
curl -fsSLO https://cdn.openttd.org/opengfx-releases/8.0/opengfx-8.0-all.zip
curl -fsSLO https://cdn.openttd.org/opensfx-releases/1.0.3/opensfx-1.0.3-all.zip
unzip -oq openttd-15.3-windows-arm64.zip
unzip -oq -d openttd-15.3-windows-arm64/baseset opengfx-8.0-all.zip
unzip -oq -d openttd-15.3-windows-arm64/baseset opensfx-1.0.3-all.zip
