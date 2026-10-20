#!/usr/bin/env bash
# تست یکپارچگی L2TP — کلاینت واقعی (L2tpClient) مقابل MockLns (رفتار MikroTik/xl2tpd)
# پیش‌نیاز: JDK 17+ و kotlinc (https://github.com/JetBrains/kotlin/releases)
set -euo pipefail
cd "$(dirname "$0")/.."

KOTLINC="${KOTLINC:-kotlinc}"
mkdir -p build

SOURCES=(
  app/src/main/java/com/securelink/app/vpn/VpnLog.kt
  app/src/main/java/com/securelink/app/vpn/l2tp/L2tpClient.kt
  app/src/main/java/com/securelink/app/vpn/l2tp/L2tpWire.kt
  app/src/main/java/com/securelink/app/vpn/l2tp/L2tpCrypto.kt
  integration-test/AndroidShims.kt
  integration-test/TestPipes.kt
  integration-test/MockLns.kt
  integration-test/Scenarios.kt
  integration-test/Main.kt
)

echo ">> compiling with $KOTLINC ..."
"$KOTLINC" "${SOURCES[@]}" -include-runtime -d build/l2tp-itest.jar

echo ">> running scenarios ..."
timeout 180 java -cp build/l2tp-itest.jar itest.MainKt
