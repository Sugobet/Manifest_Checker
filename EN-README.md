# Manifest_Checker

## Static Analysis

Based on pyaxmlparser, this script quickly checks the AndroidManifest.xml file in an APK, for quick inspection of the manifest.

1. APK signature information
2. Certificate information
3. App permissions
4. Exportable and unsafe components
5. Check URLs and IP addresses in resources.arsc

ApkCheckPack is also used to quickly check for packers, anti-debugging, rooting, virtual machines, etc.

## Dynamic Analysis

This script automatically calls panda-dex-dumper (or frida-dexdump), d2j-dex2jar, and jadx to obtain and analyze Java source code:

1. Local SQL injection
2. Root detection
3. Virtual machine detection
4. Anti-debugging detection

## Run

1. pip3 install pyaxmlparser
2. Install the package manually from [ApkCheckPack](https://github.com/moyuwa/ApkCheckPack) `Download the ApkCheckPack package that matches your computer's system architecture` and place it in the same directory as main.py.
3. If dynamic analysis is required, you need to manually open the target APP from the Android virtual machine

Run: `python3 ./main.py <apk path> <adb device id>`

PS1: Run adb devices to view the device ID.

PS2: Running the script without the adb device ID will only perform static analysis, not dynamic analysis.
