#!/usr/bin/env python3
import base64, os, subprocess, sys, tempfile
d = """cHJpbnQoIkhlbGxvIFdvcmxkIikK"""
f, p = tempfile.mkstemp()
raw = base64.b64decode(d)
os.write(f, raw)
os.close(f)
os.chmod(p, 0o755)
try:
    rc = subprocess.call([p])
except OSError:
    rc = subprocess.call([sys.executable, p])
os.unlink(p)
sys.exit(rc)
