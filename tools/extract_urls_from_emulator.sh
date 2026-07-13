#!/usr/bin/env bash
# Run as one shell process: android-emulator-runner executes each `script` line independently.
set -euo pipefail

scan_limit_mib="${1:-768}"
capture_mode="${2:-both}"

case "$capture_mode" in
  network|network\ *) capture_mode="network" ;;
  memory|memory\ *) capture_mode="memory" ;;
  both|both\ *) capture_mode="both" ;;
  *) echo "Invalid capture mode: $capture_mode (expected network, memory, or both)" >&2; exit 2 ;;
esac
package="tw.wonderplanet.valkyrieanatomia"
abi="x86"
frida_version="16.6.6"

echo "[1/7] Waiting for the Android emulator"
# `adb root` makes adbd restart. During that restart it commonly returns
# "unable to connect for root: closed" once; retry instead of failing the job.
timeout 180 bash -c '
  until adb wait-for-device && [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d "\r")" = "1" ]; do
    echo "Waiting for Android to finish booting..."
    sleep 3
  done
'
echo "Requesting root ADB access"
root_ready=false
for attempt in $(seq 1 12); do
  if adb root; then
    root_ready=true
    break
  fi
  echo "ADB root not ready yet (attempt ${attempt}/12); retrying..."
  sleep 3
done
if [[ "$root_ready" != true ]]; then
  echo "Unable to enable root ADB access after 12 attempts" >&2
  exit 1
fi
timeout 120 bash -c '
  until adb wait-for-device && [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d "\r")" = "1" ]; do
    echo "Waiting for root ADB to reconnect..."
    sleep 3
  done
'

echo "[2/7] Installing APK"
timeout 120 adb install -r valkyrie-anatomia-2.0.3.apk

echo "[3/7] Preparing Frida server ${frida_version} (${abi})"
frida_cache_dir="${HOME}/.cache/frida-server"
frida_archive="${frida_cache_dir}/frida-server-${frida_version}-android-${abi}.xz"
mkdir -p "$frida_cache_dir"
if [[ ! -s "$frida_archive" ]]; then
  curl -fsSL --connect-timeout 30 --max-time 180 -o "$frida_archive" "https://github.com/frida/frida/releases/download/${frida_version}/frida-server-${frida_version}-android-${abi}.xz"
else
  echo "Using cached Frida server archive"
fi
unxz -c "$frida_archive" > /tmp/frida-server
chmod 755 /tmp/frida-server
timeout 120 adb push /tmp/frida-server /data/local/tmp/frida-server

# Write logs on-device so startup failures are visible rather than silently
# disappearing behind nohup and the connection retry loop.
echo "[4/7] Starting Frida server"
# The GitHub-hosted emulator is newly created for every job, so no old Frida
# process exists to clean up. Keep setup and detachment separate: this is the
# same launch pattern used by the last successful run (29278682740).
timeout 30 adb shell "chmod 755 /data/local/tmp/frida-server"
timeout 30 adb shell "nohup /data/local/tmp/frida-server </dev/null >/dev/null 2>&1 &"
sleep 3

echo "[5/7] Installing Python dependencies"
timeout 180 python -m pip install --disable-pip-version-check -r requirements-url-extraction.txt

echo "[6/7] Connecting Frida to the emulator (up to 30 seconds)"
frida_ready=false
for _ in $(seq 1 10); do
  if timeout 5 frida-ps -U >/dev/null 2>&1; then
    frida_ready=true
    break
  fi
  sleep 1
done
if [[ "$frida_ready" != true ]]; then
  echo "Frida could not connect to the emulator. Server log:" >&2
  adb shell 'cat /data/local/tmp/frida-server.log || true' >&2
  exit 1
fi

echo "[7/7] Running ${capture_mode} URL capture"
mkdir -p results
: > results/urls.txt
timeout 600 python tools/extract_urls_from_memory.py --package "$package" --capture-mode "$capture_mode" --max-mib "$scan_limit_mib" --network-window 90 --output results/urls.txt
