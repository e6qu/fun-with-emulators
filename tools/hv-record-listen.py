#!/usr/bin/env python3
"""Collect fwe's flight-recorder lines streamed over UDP from another machine.

Usage: tools/hv-record-listen.py PORT [FILE]

Run it on a machine that is not running VMs, then run fwe's VM tests on the
machine under test with FWE_HV_RECORD=udp:THIS_HOST:PORT (see
docs/hypervisor.md). Each datagram is one record line; it is printed and
appended to FILE (default hv-record.log) with the time it arrived, and the
file is flushed and synced line by line, so a crash of either machine keeps
what had arrived.
"""

import os
import socket
import sys
import time


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    port = int(sys.argv[1])
    path = sys.argv[2] if len(sys.argv) == 3 else "hv-record.log"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"listening on udp port {port}, appending to {path}", file=sys.stderr)
    with open(path, "a", encoding="utf-8") as out:
        while True:
            data, (host, _) = sock.recvfrom(65536)
            line = data.decode("utf-8", "replace").rstrip("\n")
            stamped = f"{time.time():.6f} {host} {line}"
            print(stamped, flush=True)
            out.write(stamped + "\n")
            out.flush()
            os.fsync(out.fileno())


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
