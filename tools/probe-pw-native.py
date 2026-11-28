#!/usr/bin/env python3
# Probe, in debian:trixie on Linux arm64, natively: the sound test's
# PipeWire case (pw-play through PipeWire's PulseAudio tunnel to a
# PulseAudio server's null sink) 20 times; each recording's frames of
# sound, counted as the test counts them (a frame with any nonzero byte).
import os, struct, subprocess, time, math, pwd
OUT = "/out"
pa = pwd.getpwnam("pa")
def as_pa():
    os.setgid(pa.pw_gid); os.setuid(pa.pw_uid)
env = {"HOME": "/home/pa", "PATH": "/usr/bin:/bin", "XDG_RUNTIME_DIR": "/home/pa/xdg"}
os.makedirs("/home/pa/xdg", exist_ok=True); os.chown("/home/pa/xdg", pa.pw_uid, pa.pw_gid); os.chmod("/home/pa/xdg", 0o700)
# The tone: 1 s of 440 Hz then 2 s of silence, 16-bit stereo 44.1 kHz.
sound, frames = 44100, 44100 * 3
w = bytearray(b"RIFF" + struct.pack("<I", 36 + frames * 4) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, 2, 44100, 44100 * 4, 4, 16) + b"data" + struct.pack("<I", frames * 4))
for i in range(frames):
    s = int(math.sin(i / 44100 * 440 * math.tau) * 8000) if i < sound else 0
    w += struct.pack("<hh", s, s)
open("/home/pa/tone-long.wav", "wb").write(w)
conf = "/home/pa/.config/pipewire/pipewire.conf.d"
os.makedirs(conf, exist_ok=True)
open(conf + "/mac.conf", "w").write('context.modules = [\n  { name = libpipewire-module-pulse-tunnel\n    args = { tunnel.mode = sink, pulse.server.address = "unix:/home/pa/pa/native",\n             pulse.latency = 1000, node.name = mac } }\n]\n')
subprocess.run(["chown", "-R", "pa:pa", "/home/pa"], check=True)
os.makedirs("/home/pa/pa", exist_ok=True); os.chown("/home/pa/pa", pa.pw_uid, pa.pw_gid)
server = subprocess.Popen(["pulseaudio", "-n", "--daemonize=no", "--exit-idle-time=-1", "--use-pid-file=no", "--log-level=info", "--log-time=1",
    "-L", "module-null-sink sink_name=nul norewinds=1", "-L", "module-native-protocol-unix socket=/home/pa/pa/native auth-anonymous=1"],
    env=env, preexec_fn=as_pa, stdout=subprocess.DEVNULL, stderr=open(OUT + "/pa-server.txt", "w"))
while not os.path.exists("/home/pa/pa/native"): time.sleep(0.1)
script = """mkdir -p -m 700 $XDG_RUNTIME_DIR/r; export XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR/r
pipewire 2>>/out/pipewire.txt & p=$!
until [ -S $XDG_RUNTIME_DIR/pipewire-0 ]; do sleep 0.1; done
wireplumber 2>>/out/wireplumber.txt & w=$!
until pw-cli ls Node 2>/dev/null | grep -q 'node.name = "mac"'; do sleep 0.1; done
pw-play --target mac /home/pa/tone-long.wav; r=$?
kill $w $p; wait; rm -rf $XDG_RUNTIME_DIR; exit $r"""
results = []
for run in range(20):
    raw = f"/tmp/rec-{run}.raw"
    rec = subprocess.Popen(["parec", "-s", "unix:/home/pa/pa/native", "-d", "nul.monitor", "--latency-msec=20", "--format=s16le", "--rate=44100", "--channels=2", "--raw"],
        env=env, preexec_fn=as_pa, stdout=open(raw, "wb"), stderr=subprocess.DEVNULL)
    while os.path.getsize(raw) == 0: time.sleep(0.05)
    r = subprocess.run(["sh", "-c", script], env=env, preexec_fn=as_pa)
    time.sleep(1)
    rec.send_signal(2); rec.wait()
    d = open(raw, "rb").read()
    fr = [d[i:i + 4] for i in range(0, len(d) - 3, 4)]
    loud = [any(f) for f in fr]
    n = sum(loud)
    first = loud.index(True) if n else None
    last = len(loud) - 1 - loud[::-1].index(True) if n else None
    results.append(n)
    print(f"native run {run}: pw-play {r.returncode}, {n} frames of sound in {len(fr)}, from {first} to {last}", flush=True)
print("native: below 43000 in", sum(1 for n in results if n <= 43000), "of", len(results), "; sorted:", sorted(results), flush=True)
server.terminate()
