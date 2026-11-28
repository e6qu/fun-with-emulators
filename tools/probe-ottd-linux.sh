#!/bin/sh
# Probe, inside alpine:3.24 on Linux arm64: OpenTTD under Wine natively,
# without and with a PulseAudio server; 3 minutes each, screenshots.
set -u
apk add -q wine font-dejavu libpulse libxcursor libxi libxinerama libxrandr libxcomposite \
  xvfb xdotool imagemagick pulseaudio pulseaudio-utils curl unzip mesa-dri-gallium > /out/apk.txt 2>&1
sh /work/tools/probe-ottd-common.sh /root
Xvfb :4 -screen 0 1024x768x24 -nolisten tcp > /out/xvfb.txt 2>&1 &
sleep 3
export DISPLAY=:4 WINEDLLOVERRIDES="mscoree,mshtml=" HOME=/root
t0=$(date +%s); wineboot -i > /out/wineboot.txt 2>&1; echo "linux wineboot: $(( $(date +%s) - t0 )) s"
run() {  # $1 tag
  WINEDEBUG=+timestamp,+mmdevapi,+pulse,+alsa,+xaudio2 timeout 180 wine /root/openttd-15.3-windows-arm64/openttd.exe -d driver=9,misc=2 > "/out/$1.txt" 2>&1 &
  w=$!
  for m in 1 2 3; do sleep 55; import -window root "/out/$1-$m.png" 2>/dev/null
    echo "linux $1 minute $m: $(xdotool search --name OpenTTD 2>/dev/null | tr '\n' ' ') $(grep -c -a -i 'EXCEPTION\|crash' /out/$1.txt) crash lines"; done
  wait "$w"; wineserver -k 2>/dev/null; sleep 2
}
adduser -D pa
su pa -c 'HOME=/tmp/pa pulseaudio -n --daemonize=no --exit-idle-time=-1 --use-pid-file=no -L "module-null-sink sink_name=nul" -L "module-native-protocol-unix socket=/tmp/pa.sock auth-anonymous=1"' > /out/pa-server.txt 2>&1 &
for i in $(seq 30); do [ -S /tmp/pa.sock ] && break; sleep 1; done
ls -la /tmp/pa.sock
PULSE_SERVER=unix:/tmp/pa.sock run pulse
