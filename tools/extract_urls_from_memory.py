#!/usr/bin/env python3
"""Attach Frida to an Android process and save http(s) URLs from readable memory."""
import argparse
import re
import time
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
const MAX = %d;
let scanned = 0;
for (const range of Process.enumerateRanges({protection: "r--", coalesce: true})) {
  if (MAX && scanned >= MAX) break;
  let offset = 0;
  while (offset < range.size && (!MAX || scanned < MAX)) {
    const size = Math.min(CHUNK, range.size - offset, MAX ? MAX - scanned : CHUNK);
    try {
      const bytes = new Uint8Array(Memory.readByteArray(range.base.add(offset), size));
      const found = decoder.decode(bytes).match(urlRe);
      if (found) for (const url of found) send(url);
    } catch (_) {}
    offset += size;
    scanned += size;
  }
}
send({done: true, scanned: scanned});
''' % limit

urls = set()
def on_message(message, data):
    if message["type"] == "send" and isinstance(message["payload"], str):
        url = message["payload"].rstrip(".,;:)]}\\\"")
        if re.match(r"^https?://", url, re.I):
            urls.add(url)
    elif message["type"] == "error":
        print(message.get("stack", message))

device = frida.get_usb_device(timeout=30)
session = device.attach(args.pid)
script = session.create_script(script_source)
script.on("message", on_message)
script.load()
time.sleep(3)
script.unload()
session.detach()

out = Path(args.output)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("# URLs extracted from readable memory\n" + "\n".join(sorted(urls)) + "\n", encoding="utf-8")
print(f"Saved {len(urls)} unique URLs to {out}")
