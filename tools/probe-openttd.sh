#!/bin/bash
# Probe: OpenTTD's README steps on the stand-in, its two video drivers.
set -u
FWE="$PWD/target/release/fwe"
LIB="$(brew --prefix libx11)/lib/libX11.6.dylib"
export DISPLAY=:4
mkdir -p out
[ -d ~/alpine ] || "$FWE" --pull alpine:3.24 ~/alpine
env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin "$FWE" --root ~/alpine ~/alpine/bin/sh -c \
  'apk add -q wine font-dejavu libpulse libxcursor libxi libxinerama libxrandr libxcomposite' > out/apk.txt 2>&1
(
  cd ~/alpine/root
  curl -fsSLO https://cdn.openttd.org/openttd-releases/15.3/openttd-15.3-windows-arm64.zip
  curl -fsSLO https://cdn.openttd.org/opengfx-releases/8.0/opengfx-8.0-all.zip
  curl -fsSLO https://cdn.openttd.org/opensfx-releases/1.0.3/opensfx-1.0.3-all.zip
  unzip -oq openttd-15.3-windows-arm64.zip
  unzip -oq -d openttd-15.3-windows-arm64/baseset opengfx-8.0-all.zip
  unzip -oq -d openttd-15.3-windows-arm64/baseset opensfx-1.0.3-all.zip
)
t0=$(date +%s)
env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:4 WINEDLLOVERRIDES="mscoree,mshtml=" \
  "$FWE" --hv-standin --vm --root ~/alpine ~/alpine/bin/sh -c 'wineboot -i' > out/wineboot.txt 2>&1
echo "wineboot: $(( $(date +%s) - t0 )) s, status $?"
watch() {  # $1 tag, $2 minutes
  for m in $(seq "$2"); do
    sleep 60
    /opt/X11/bin/xwininfo -root -tree > "out/$1-tree-$m.txt" 2>&1
    id=$(xdotool search --onlyvisible --name OpenTTD 2>/dev/null | head -1)
    if [ -n "$id" ]; then
      python3 tools/display/shot.py "$LIB" :4 "out/$1-$m.png" window "$id" | head -1 | sed "s/^/$1 minute $m window $id: /"
    else
      echo "$1 minute $m: no OpenTTD window; $(grep -oE '\"[^\"]+\"' out/$1-tree-$m.txt | sort -u | tr '\n' ' ' | cut -c1-200)"
    fi
    screencapture -x "out/$1-screen-$m.png" 2>/dev/null
  done
}
for drv in default win32; do
  args="-d 2"
  [ "$drv" = win32 ] && args="-v win32 -d 2"
  env -i HOME=/root PATH=/usr/bin:/bin DISPLAY=:4 WINEDLLOVERRIDES="mscoree,mshtml=" \
    "$FWE" --hv-standin --vm --root ~/alpine ~/alpine/bin/sh -c "wine /root/openttd-15.3-windows-arm64/openttd.exe $args" \
    > "out/$drv.txt" 2>&1 &
  p=$!
  watch "$drv" 20
  [ "$p" -gt 0 ] && kill "$p"
  sleep 5
  for q in $(pgrep -f "alpine/bin/sh -c wine|wineserver|openttd.exe"); do [ "$q" -gt 0 ] && kill -9 "$q"; done
  sleep 5
done
