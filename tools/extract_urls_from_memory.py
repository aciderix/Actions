#!/usr/bin/env python3
"""Capture Android network URLs and URLs found in readable process memory via Frida."""
import argparse
import re
import threading
from pathlib import Path

import frida

parser = argparse.ArgumentParser()
target = parser.add_mutually_exclusive_group(required=True)
target.add_argument("--pid", type=int)
target.add_argument("--package", help="Package to spawn suspended, then observe from launch")
parser.add_argument("--output", required=True)
parser.add_argument("--capture-mode", choices=("network", "memory", "both"), default="both")
parser.add_argument("--max-mib", type=int, default=768, help="Maximum readable memory scanned; 0 means no cap")
parser.add_argument("--network-window", type=int, default=90, help="Seconds to observe network calls after launch")
args = parser.parse_args()

# URLs may straddle two memory reads. Keep enough trailing bytes to reconstruct
# even the longest URL accepted below, without repeatedly scanning whole chunks.
CHUNK_OVERLAP = 4096
ASCII_URL_RE = re.compile(rb'https?://[^\s\x00"\x27<>\\\\]{4,2048}', re.I)
UTF16LE_URL_RE = re.compile(
    rb'h\x00t\x00t\x00p\x00s?\x00:\x00/\x00/\x00(?:(?:[^\x00\s"\x27<>\\\\])\x00){4,2048}',
    re.I,
)

capture_network = args.capture_mode in ("network", "both")
capture_memory = args.capture_mode in ("memory", "both")
limit = args.max_mib * 1024 * 1024 if capture_memory and args.max_mib else 0
window_ms = max(0, args.network_window) * 1000 if capture_network else 0
script_source = r'''
const CHUNK = 1024 * 1024;
const MAX = %d;
const NETWORK_WINDOW = %d;
const CAPTURE_NETWORK = %s;
const CAPTURE_MEMORY = %s;

function report(kind, value) {
  if (value) send({kind: kind, value: String(value)});
}

function hookNetwork() {
  if (!Java.available) return;
  Java.perform(function () {
    try {
      const URL = Java.use("java.net.URL");
      const noProxy = URL.openConnection.overload();
      noProxy.implementation = function () {
        report("network", this.toString());
        return noProxy.call(this);
      };
      const withProxy = URL.openConnection.overload("java.net.Proxy");
      withProxy.implementation = function (proxy) {
        report("network", this.toString());
        return withProxy.call(this, proxy);
      };
    } catch (_) {}
    try {
      const URLConnection = Java.use("java.net.URLConnection");
      const connect = URLConnection.connect.overload();
      connect.implementation = function () {
        report("network", this.getURL().toString());
        return connect.call(this);
      };
    } catch (_) {}
    try {
      const OkHttpClient = Java.use("okhttp3.OkHttpClient");
      const newCall = OkHttpClient.newCall.overload("okhttp3.Request");
      newCall.implementation = function (request) {
        report("network", request.url().toString());
        return newCall.call(this, request);
      };
    } catch (_) {}
    try {
      const WebView = Java.use("android.webkit.WebView");
      const loadUrl = WebView.loadUrl.overload("java.lang.String");
      loadUrl.implementation = function (url) {
        report("network", url);
        return loadUrl.call(this, url);
      };
    } catch (_) {}
  });
}

if (CAPTURE_NETWORK) hookNetwork();
const ranges = [];
if (CAPTURE_MEMORY) {
  for (const protection of ["rw-", "r--", "r-x"]) {
    for (const range of Process.enumerateRanges({protection: protection, coalesce: true})) ranges.push(range);
  }
}
let scanned = 0;
let rangeIndex = 0;
let offset = 0;
let memoryDone = !CAPTURE_MEMORY;
let timerDone = !CAPTURE_NETWORK || NETWORK_WINDOW === 0;

function finishIfReady() {
  if (memoryDone && timerDone) send({kind: "done", scanned: scanned});
}
function completeMemory() {
  memoryDone = true;
  finishIfReady();
}
function scanNext() {
  if (rangeIndex >= ranges.length || (MAX && scanned >= MAX)) {
    completeMemory();
    return;
  }
  const range = ranges[rangeIndex];
  if (offset >= range.size) {
    rangeIndex++;
    offset = 0;
    setImmediate(scanNext);
    return;
  }
  const size = Math.min(CHUNK, range.size - offset, MAX ? MAX - scanned : CHUNK);
  offset += size;
  scanned += size;
  try {
    const bytes = Memory.readByteArray(range.base.add(offset - size), size);
    // Do no string conversion or regex work in QuickJS. Python receives this
    // binary buffer, scans it, then explicitly allows the next chunk.
    recv("ack", function () { setImmediate(scanNext); });
    send({kind: "memory-chunk", size: size}, bytes);
  } catch (_) {
    setImmediate(scanNext);
  }
}
if (CAPTURE_NETWORK && NETWORK_WINDOW > 0) {
  setTimeout(function () { timerDone = true; finishIfReady(); }, NETWORK_WINDOW);
}
if (CAPTURE_MEMORY) {
  setImmediate(scanNext);
} else {
  finishIfReady();
}
''' % (limit, window_ms, str(capture_network).lower(), str(capture_memory).lower())

memory_urls = set()
network_urls = set()
done = threading.Event()
scan_result = {}
previous_bytes = b""


def normalise(value):
    return value.rstrip(".,;:)]}\\\"")


def add_memory_matches(data):
    global previous_bytes
    combined = previous_bytes + bytes(data)
    for match in ASCII_URL_RE.finditer(combined):
        memory_urls.add(normalise(match.group().decode("ascii", errors="ignore")))
    for match in UTF16LE_URL_RE.finditer(combined):
        memory_urls.add(normalise(match.group().decode("utf-16le", errors="ignore")))
    previous_bytes = combined[-CHUNK_OVERLAP:]


def on_message(message, data):
    if message["type"] == "send" and isinstance(message["payload"], dict):
        payload = message["payload"]
        kind = payload.get("kind")
        if kind == "memory-chunk":
            try:
                if data:
                    add_memory_matches(data)
            finally:
                # Back-pressure keeps Frida responsive and caps in-flight data
                # to one chunk while Python handles the binary regex search.
                script.post({"type": "ack"})
        elif kind == "network":
            url = normalise(payload.get("value", ""))
            if re.match(r"^https?://", url, re.I):
                network_urls.add(url)
        elif kind == "done":
            scan_result.update(payload)
            done.set()
    elif message["type"] == "error":
        print(message.get("stack", message))
        done.set()


device = frida.get_usb_device(timeout=30)
pid = device.spawn([args.package]) if args.package else args.pid
session = device.attach(pid)
script = session.create_script(script_source)
script.on("message", on_message)
script.load()
if args.package:
    device.resume(pid)
if not done.wait(timeout=8 * 60):
    script.unload()
    session.detach()
    raise TimeoutError("Memory scan and network observation did not finish within 8 minutes")
script.unload()
session.detach()

out = Path(args.output)
out.parent.mkdir(parents=True, exist_ok=True)
sections = []
if capture_memory:
    sections.append("# URLs extracted from readable memory\n" + "\n".join(sorted(memory_urls)))
if capture_network:
    sections.append("# Network calls captured during app launch\n" + "\n".join(sorted(network_urls)))
out.write_text("\n\n".join(sections) + "\n", encoding="utf-8")
print(
    f"Mode {args.capture_mode}; scanned {scan_result.get('scanned', 0)} bytes; "
    f"saved {len(memory_urls)} memory URLs and {len(network_urls)} network calls to {out}"
)
