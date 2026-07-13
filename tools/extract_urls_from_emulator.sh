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

timeout 90 adb wait-for-device
timeout 60 adb root
timeout 90 adb wait-for-device
timeout 120 adb install -r valkyrie-anatomia-2.0.3.apk
curl -fsSL --connect-timeout 30 --max-time 180 -o /tmp/frida-server.xz "https://github.com/frida/frida/releases/download/${frida_version}/frida-server-${frida_version}-android-${abi}.xz"
unxz -f /tmp/frida-server.xz
timeout 120 adb push /tmp/frida-server /data/local/tmp/frida-server

# Keep setup and detachment separate: adb must be able to close immediately
# after starting frida-server on the emulator.
timeout 30 adb shell "chmod 755 /data/local/tmp/frida-server"
timeout 30 adb shell "nohup /data/local/tmp/frida-server </dev/null >/dev/null 2>&1 &"
sleep 3

timeout 180 python -m pip install --disable-pip-version-check "frida==${frida_version}" frida-tools
for _ in $(seq 1 15); do
  timeout 15 frida-ps -U >/dev/null 2>&1 && break
  sleep 1
done
timeout 15 frida-ps -U >/dev/null
mkdir -p results
: > results/urls.txt
timeout 600 python tools/extract_urls_from_memory.py --package "$package" --capture-mode "$capture_mode" --max-mib "$scan_limit_mib" --network-window 90 --output results/urls.txt
