# Manifest_Checker

[EN-README](./EN-README.md)

## Static Analysis

基于pyaxmlparser，APK的AndroidManifest.xml快速检查脚本，用于快速检查Manifest中的信息

1. APK签名信息
2. 证书信息
3. 应用权限
4. 可导出及不安全的组件
5. 检查resources.arsc中的url和ip

另外调用了ApkCheckPack，用于快速检查加壳、反调试、root、虚拟机等

## Dynamic Analysis

通过自动调用panda-dex-dumper（或frida-dexdump）、d2j-dex2jar、jadx，获得java源码并分析：

1. 本地sql注入
2. root检测
3. 虚拟机检测
4. 反调试检测

## Run

  1. pip3 install pyaxmlparser
  2. 自行从 [ApkCheckPack](https://github.com/moyuwa/ApkCheckPack) `下载适合自己电脑系统架构`的ApkCheckPack并放到main.py同级目录
  3. 若需要动态分析，则需要手动从安卓虚拟机打开目标APP

运行: `python3 ./main.py <apk path> <adb device id>`

ps1: 运行adb devices查看id

ps2: 运行脚本时不提供adb device id则只会进行静态分析，不会做动态分析
