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
parser.add_argument("--max-mib", type=int, default=768, help="Maximum readable memory scanned; 0 means no cap")
parser.add_argument("--network-window", type=int, default=90, help="Seconds to observe network calls after launch")
args = parser.parse_args()

limit = args.max_mib * 1024 * 1024 if args.max_mib else 0
window_ms = max(0, args.network_window) * 1000
script_source = r'''
const urlRe = /https?:\/\/[^\s\x00"\x27<>\\]{4,2048}/g;
const CHUNK = 1024 * 1024;
const BATCH = 8;
const MAX = %d;
const NETWORK_WINDOW = %d;

function report(kind, value) {
  if (value) send({kind: kind, value: String(value)});
}

// Frida's QuickJS runtime does not provide TextDecoder. URLs are ASCII, so a
// byte-to-ASCII conversion is sufficient and avoids the unavailable API.
function ascii(bytes, step) {
  let text = "";
  for (let i = 0; i < bytes.length; i += step) {
    const value = bytes[i];
    text += value < 128 ? String.fromCharCode(value) : " ";
  }
  return text;
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

hookNetwork();
const ranges = [];
for (const protection of ["rw-", "r--", "r-x"]) {
  for (const range of Process.enumerateRanges({protection: protection, coalesce: true})) ranges.push(range);
}
let scanned = 0;
let rangeIndex = 0;
let offset = 0;
let memoryDone = false;
let timerDone = NETWORK_WINDOW === 0;
function finishIfReady() {
  if (memoryDone && timerDone) send({kind: "done", scanned: scanned});
}
function scanBatch() {
  let chunks = 0;
  while (rangeIndex < ranges.length && (!MAX || scanned < MAX) && chunks++ < BATCH) {
    const range = ranges[rangeIndex];
    if (offset >= range.size) { rangeIndex++; offset = 0; continue; }
    const size = Math.min(CHUNK, range.size - offset, MAX ? MAX - scanned : CHUNK);
    try {
      const bytes = new Uint8Array(Memory.readByteArray(range.base.add(offset), size));
      const found = new Set();
      for (const text of [ascii(bytes, 1), ascii(bytes, 2)]) {
        const matches = text.match(urlRe);
        if (matches) for (const url of matches) found.add(url);
      }
      for (const url of found) report("memory", url);
    } catch (_) {}
    offset += size;
    scanned += size;
  }
  if (rangeIndex >= ranges.length || (MAX && scanned >= MAX)) {
    memoryDone = true;
    finishIfReady();
  } else setImmediate(scanBatch);
}
setTimeout(function () { timerDone = true; finishIfReady(); }, NETWORK_WINDOW);
setImmediate(scanBatch);
''' % (limit, window_ms)

memory_urls = set()
network_urls = set()
done = threading.Event()
scan_result = {}

def normalise(value):
    return value.rstrip(".,;:)]}\\\"")

def on_message(message, data):
    if message["type"] == "send" and isinstance(message["payload"], dict):
        payload = message["payload"]
        if payload.get("kind") in {"memory", "network"}:
            url = normalise(payload.get("value", ""))
            if re.match(r"^https?://", url, re.I):
                (memory_urls if payload["kind"] == "memory" else network_urls).add(url)
        elif payload.get("kind") == "done":
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
if not done.wait(timeout=20 * 60):
    script.unload()
    session.detach()
    raise TimeoutError("Memory scan and network observation did not finish within 20 minutes")
script.unload()
session.detach()

out = Path(args.output)
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(
    "# URLs extracted from readable memory\n" + "\n".join(sorted(memory_urls)) +
    "\n\n# Network calls captured during app launch\n" + "\n".join(sorted(network_urls)) + "\n",
    encoding="utf-8",
)
print(f"Scanned {scan_result.get('scanned', 0)} bytes; saved {len(memory_urls)} memory URLs and {len(network_urls)} network calls to {out}")
