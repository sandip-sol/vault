#!/usr/bin/env bash
# ============================================================
#  SafeVault — Full Android Emulator Setup & Run
#  Run this script once in your terminal:
#    chmod +x setup_and_run.sh && ./setup_and_run.sh
# ============================================================
set -e

ANDROID_HOME="$HOME/Android/Sdk"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
AVD_NAME="SafeVault_AVD"
PACKAGE_SYS_IMG="system-images;android-34;google_apis;x86_64"

echo "============================================================"
echo " Step 1: Install Java 17 JDK"
echo "============================================================"
sudo apt-get update -qq
sudo apt-get install -y openjdk-17-jdk wget unzip libgl1 libpulse0 libxcomposite1 libxcursor1 libxi6 libxtst6

export JAVA_HOME=$(update-java-alternatives -l | grep 17 | awk '{print $3}')
export PATH="$JAVA_HOME/bin:$PATH"
java -version

echo ""
echo "============================================================"
echo " Step 2: Download Android Command-line Tools"
echo "============================================================"
mkdir -p "$ANDROID_HOME/cmdline-tools"
cd /tmp
wget -q --show-progress -O cmdline-tools.zip "$CMDLINE_TOOLS_URL"
unzip -q -o cmdline-tools.zip -d "$ANDROID_HOME/cmdline-tools"
mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" 2>/dev/null || true

export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

echo ""
echo "============================================================"
echo " Step 3: Accept Licenses & Install SDK Components"
echo "============================================================"
yes | sdkmanager --licenses > /dev/null 2>&1 || true
sdkmanager --install \
  "platform-tools" \
  "emulator" \
  "platforms;android-34" \
  "build-tools;34.0.0" \
  "$PACKAGE_SYS_IMG"

echo ""
echo "============================================================"
echo " Step 4: Create Android Virtual Device (AVD)"
echo "============================================================"
echo "no" | avdmanager create avd \
  --name "$AVD_NAME" \
  --package "$PACKAGE_SYS_IMG" \
  --device "pixel_6" \
  --force

echo ""
echo "============================================================"
echo " Step 5: Build SafeVault APK"
echo "============================================================"
cd "$HOME/pvt_workspace/SafeVault"
chmod +x gradlew
./gradlew assembleDebug

APK_PATH="app/build/outputs/apk/debug/app-debug.apk"
echo "APK built: $APK_PATH"

echo ""
echo "============================================================"
echo " Step 6: Launch Emulator (headless)"
echo "============================================================"
# start emulator in background
nohup "$ANDROID_HOME/emulator/emulator" \
  -avd "$AVD_NAME" \
  -no-snapshot-save \
  -no-audio \
  -gpu swiftshader_indirect \
  > /tmp/emulator.log 2>&1 &

echo "Waiting for emulator to boot (up to 3 minutes)..."
"$ANDROID_HOME/platform-tools/adb" wait-for-device
# wait for full boot
until "$ANDROID_HOME/platform-tools/adb" shell getprop sys.boot_completed 2>/dev/null | grep -q "1"; do
  sleep 3
  echo -n "."
done
echo ""
echo "Emulator is ready!"

echo ""
echo "============================================================"
echo " Step 7: Install & Launch SafeVault"
echo "============================================================"
"$ANDROID_HOME/platform-tools/adb" install -r "$HOME/pvt_workspace/SafeVault/$APK_PATH"
"$ANDROID_HOME/platform-tools/adb" shell am start -n "com.safevault.app/.ui.UnlockActivity"

echo ""
echo "✅  SafeVault is now running on the Android emulator!"
echo "    Check the emulator window."
