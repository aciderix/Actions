#!/usr/bin/env bash
# Run as one shell process: android-emulator-runner executes each `script` line independently.
set -euo pipefail

scan_limit_mib="${1:-768}"
package="tw.wonderplanet.valkyrieanatomia"
abi="x86"
frida_version="16.6.6"

adb wait-for-device
adb root
adb wait-for-device
adb install -r valkyrie-anatomia-2.0.3.apk
curl -fsSL -o /tmp/frida-server.xz "https://github.com/frida/frida/releases/download/${frida_version}/frida-server-${frida_version}-android-${abi}.xz"
unxz -f /tmp/frida-server.xz
adb push /tmp/frida-server /data/local/tmp/frida-server

# Keep setup and detachment separate: adb must be able to close immediately
# after starting frida-server on the emulator.
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "nohup /data/local/tmp/frida-server </dev/null >/dev/null 2>&1 &"
sleep 3

python -m pip install --disable-pip-version-check "frida==${frida_version}" frida-tools
for _ in $(seq 1 15); do
  frida-ps -U >/dev/null 2>&1 && break
  sleep 1
done
frida-ps -U >/dev/null
mkdir -p results
: > results/urls.txt
python tools/extract_urls_from_memory.py --package "$package" --max-mib "$scan_limit_mib" --network-window 90 --output results/urls.txt
