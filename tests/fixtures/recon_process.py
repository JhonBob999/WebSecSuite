"""Harmless local process fixture. Never opens a socket or invokes a scanner."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time


mode = sys.argv[1]
if mode == "success":
    print("controlled stdout", flush=True)
    print("controlled stderr", file=sys.stderr, flush=True)
elif mode == "nonzero":
    print("controlled failure", file=sys.stderr, flush=True)
    sys.exit(7)
elif mode == "sleep":
    print("ready", flush=True)
    time.sleep(60)
elif mode in {"tree", "tree_exit"}:
    child = subprocess.Popen([sys.executable, "-u", __file__, "child"])
    print(f"parent {os.getpid()}", flush=True)
    time.sleep(0.5 if mode == "tree_exit" else 60)
elif mode == "child":
    print(f"child {os.getpid()}", flush=True)
    time.sleep(60)
elif mode == "marker":
    Path(sys.argv[2]).write_text("unexpected execution", encoding="utf-8")
elif mode == "flood":
    for _ in range(100):
        os.write(sys.stdout.fileno(), b"x" * 4096)
        os.write(sys.stderr.fileno(), b"y" * 4096)
elif mode == "arguments":
    print(json.dumps(sys.argv[2:]), flush=True)
elif mode == "environment":
    print(json.dumps({"environment": dict(os.environ), "directory": os.getcwd()}), flush=True)
