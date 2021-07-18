#!/usr/bin/env python3

import json
import socket
import sys

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        s.connect(("127.0.0.1", 1717))

        data = b""
        while True:
            recv = s.recv(4096)
            data += recv
            if len(recv) < 4096:
                break
except OSError:
    print("Error connecting to stats server.")
    sys.exit(1)

parsed = json.loads(data.decode("utf-8"))
if "pid" in parsed:
    sys.exit(0)
sys.exit(1)
