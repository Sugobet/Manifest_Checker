# Manifest_Checker

基于pyaxmlparser，APK的AndroidManifest.xml快速检查脚本，用于快速检查Manifest中的信息

Based on pyaxmlparser, this script quickly checks the AndroidManifest.xml of an APK. It is used to quickly check the information in the manifest.

1. APK签名信息  APK signature information
2. 证书信息  Certificate information
3. 应用权限  App permissions
4. 可导出及不安全的组件  Exportable and unsafe components
5. 检查resources.arsc中的url和ip  Check the URLs and IP addresses in resources.arsc

另外调用了ApkCheckPack，用于快速检查加壳、反调试、root、虚拟机等

ApkCheckPack is also used to quickly check for packers, anti-debugging, rooting, virtual machines, etc.

## Run

  1. pip3 install pyaxmlparser
  2. 自行从 [ApkCheckPack](https://github.com/moyuwa/ApkCheckPack) 下载ApkCheckPack并放到main.py同级目录      Download ApkCheckPack from [ApkCheckPack](https://github.com/moyuwa/ApkCheckPack) and place it in the same directory as main.py.

Run: `python3 ./main.py <apk path>`
