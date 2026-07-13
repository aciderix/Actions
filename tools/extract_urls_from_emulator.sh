#!/usr/bin/env bash
# Run as one shell process: android-emulator-runner executes each `script` line independently.
set -euo pipefail

scan_limit_mib="${1:-768}"
package="tw.wonderplanet.valkyrieanatomia"
activity="jp.libtest.SplashActivity_default"
abi="x86"
frida_version="16.6.6"

adb wait-for-device
adb root
adb wait-for-device
adb install -r valkyrie-anatomia-2.0.3.apk
adb shell am start -n "${package}/${activity}"

pid=""
for _ in $(seq 1 40); do
  pid="$(adb shell pidof "$package" | tr -d "\r" | awk '{print $1}')"
  [ -n "$pid" ] && break
  sleep 3
done

if [ -z "$pid" ]; then
  echo "The application did not start; logcat:" >&2
  adb logcat -d -t 500 >&2 || true
  exit 1
fi

curl -fsSL -o /tmp/frida-server.xz "https://github.com/frida/frida/releases/download/${frida_version}/frida-server-${frida_version}-android-${abi}.xz"
unxz -f /tmp/frida-server.xz
adb push /tmp/frida-server /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server >/dev/null 2>&1 &"

python -m pip install --disable-pip-version-check "frida==${frida_version}"
for _ in $(seq 1 15); do
  frida-ps -U >/dev/null 2>&1 && break
  sleep 1
done
frida-ps -U >/dev/null
python tools/extract_urls_from_memory.py --pid "$pid" --max-mib "$scan_limit_mib" --output results/urls.txt
