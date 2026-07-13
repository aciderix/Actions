#!/usr/bin/env python3
"""Attach Frida to an Android process and save http(s) URLs from readable memory."""
import argparse
import re
import time
import threading
from pathlib import Path

import frida

parser = argparse.ArgumentParser()
parser.add_argument("--pid", type=int, required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--max-mib", type=int, default=768, help="Maximum readable memory scanned; 0 means no cap")
args = parser.parse_args()

limit = args.max_mib * 1024 * 1024 if args.max_mib else 0
script_source = r'''
const urlRe = /https?:\/\/[^\s\x00"\x27<>\\]{4,2048}/g;
const decoder = new TextDecoder("utf-8", {fatal: false});
const CHUNK = 1024 * 1024;
const BATCH = 8;
const MAX = %d;
// Android application heaps and live network buffers are normally rw-.
// Scan them first, before read-only and executable mappings, so the optional
// byte limit prioritizes the process data most likely to contain live URLs.
const ranges = [];
for (const protection of ["rw-", "r--", "r-x"]) {
  for (const range of Process.enumerateRanges({protection: protection, coalesce: true})) {
    ranges.push(range);
  }
}
let scanned = 0;
let rangeIndex = 0;
let offset = 0;
function scanBatch() {
  let chunks = 0;
  while (rangeIndex < ranges.length && (!MAX || scanned < MAX) && chunks++ < BATCH) {
    const range = ranges[rangeIndex];
    if (offset >= range.size) { rangeIndex++; offset = 0; continue; }
    const size = Math.min(CHUNK, range.size - offset, MAX ? MAX - scanned : CHUNK);
    try {
      const bytes = new Uint8Array(Memory.readByteArray(range.base.add(offset), size));
      const found = decoder.decode(bytes).match(urlRe);
      if (found) for (const url of found) send(url);
    } catch (_) {}
    offset += size;
    scanned += size;
  }
  if (rangeIndex >= ranges.length || (MAX && scanned >= MAX)) {
    send({done: true, scanned: scanned});
  } else {
    setImmediate(scanBatch);
  }
}
setImmediate(scanBatch);
''' % limit

urls = set()
done = threading.Event()
scan_result = {}
def on_message(message, data):
    if message["type"] == "send" and isinstance(message["payload"], str):
        url = message["payload"].rstrip(".,;:)]}\\\"")
        if re.match(r"^https?://", url, re.I):
            urls.add(url)
    elif message["type"] == "send" and isinstance(message["payload"], dict) and message["payload"].get("done"):
        scan_result.update(message["payload"])
        done.set()
    elif message["type"] == "error":
        print(message.get("stack", message))
        done.set()

device = frida.get_usb_device(timeout=30)
session = device.attach(args.pid)
script = session.create_script(script_source)
script.on("message", on_message)
script.load()
if not done.wait(timeout=20 * 60):
    script.unload()
    session.detach()
    raise TimeoutError("Memory scan did not finish within 20 minutes")
script.unload()
session.detach()

out = Path(args.output)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("# URLs extracted from readable memory\n" + "\n".join(sorted(urls)) + "\n", encoding="utf-8")
print(f"Scanned {scan_result.get('scanned', 0)} bytes; saved {len(urls)} unique URLs to {out}")
