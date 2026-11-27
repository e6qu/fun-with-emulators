#!/bin/bash
# Probe: OpenTTD's README steps on the stand-in (release fwe), without and
# with a PulseAudio server as the README test runs one; traces Wine's sound.
set -u
FWE="$PWD/target/release/fwe"
mkdir -p out
[ -d ~/alpine ] || "$FWE" --pull alpine:3.24 ~/alpine
env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin "$FWE" --root ~/alpine ~/alpine/bin/sh -c \
  'apk add -q wine font-dejavu libpulse libxcursor libxi libxinerama libxrandr libxcomposite' > out/apk.txt 2>&1
sh tools/probe-ottd-common.sh ~/alpine/root
t0=$(date +%s)
env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:4 WINEDLLOVERRIDES="mscoree,mshtml=" \
  "$FWE" --hv-standin --vm --root ~/alpine ~/alpine/bin/sh -c 'wineboot -i' > out/wineboot.txt 2>&1
echo "mac wineboot: $(( $(date +%s) - t0 )) s"
run() {  # $1 tag, then env for fwe
  tag=$1; shift
  env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:4 WINEDLLOVERRIDES="mscoree,mshtml=" "$@" \
    "$FWE" --hv-standin --vm --root ~/alpine ~/alpine/bin/sh -c \
    'WINEDEBUG=+timestamp,+mmdevapi,+pulse,+alsa,+xaudio2 wine /root/openttd-15.3-windows-arm64/openttd.exe -d driver=9,misc=2' \
    > "out/$tag.txt" 2>&1 &
  p=$!
  for m in $(seq 15); do sleep 60; screencapture -x "out/$tag-$m.png" 2>/dev/null
    echo "mac $tag minute $m: $(wc -l < out/$tag.txt) lines, last: $(tail -1 out/$tag.txt | cut -c1-150)"; done
  [ "$p" -gt 0 ] && kill "$p"; sleep 5
  for q in $(pgrep -f "wineserver|openttd.exe|alpine/bin/sh -c"); do [ "$q" -gt 0 ] && kill -9 "$q"; done
  sleep 5
}
run nosound
PA=$(brew --prefix pulseaudio)/bin/pulseaudio
D=$(mktemp -d /tmp/pa.XXXX)
env -i HOME="$D" "$PA" -n --daemonize=no --exit-idle-time=-1 --use-pid-file=no --log-level=info --log-time=1 \
  -L "module-null-sink sink_name=nul norewinds=1" -L "module-native-protocol-unix socket=$D/native" \
  > out/pa-server.txt 2>&1 &
for i in $(seq 30); do [ -S "$D/native" ] && break; sleep 1; done
run pulse PULSE_SERVER="unix:$D/native" PULSE_COOKIE="$D/.config/pulse/cookie"
