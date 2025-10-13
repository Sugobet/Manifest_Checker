import re
import argparse
import zipfile
import hashlib

from pyaxmlparser.axmlprinter import AXMLPrinter
from pyaxmlparser.utils import NS_ANDROID, get_certificate_name_string
from pyaxmlparser.arscparser import ARSCParser
from pyaxmlparser import APK

def print_header(title):
    print("\n" + "="*60)
    print(f"[*] {title}")
    print("="*60)

def print_success(message):
    print(f"[+] {message}")

def print_warning(message):
    print(f"[-] \033[93mWARNING: {message}\033[0m")

def print_info(message):
    print(f"    {message}")

def analyze_manifest(apk_path):
    issue_counts = {
        "permissions": 0,
        "debuggable": 0,
        "allow_backup": 0,
        "insecure_components": 0
    }
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            if 'AndroidManifest.xml' not in apk_zip.namelist():
                print("Fatal Error: AndroidManifest.xml not found in APK.")
                return {}
            manifest_data = apk_zip.read('AndroidManifest.xml')
    except Exception as e:
        print(f"Failed to read APK file: {e}")
        return {}

    try:
        axml_obj = AXMLPrinter(manifest_data).get_xml_obj()
    except Exception as e:
        print(f"Failed to parse AndroidManifest.xml: {e}")
        return {}

    nsmap = {'android': NS_ANDROID}

    print_header("Scanning Android Permissions")
    permission_nodes = axml_obj.findall("uses-permission")
    permissions = []
    if permission_nodes:
        for node in permission_nodes:
            perm_name = node.get(NS_ANDROID + 'name')
            if perm_name:
                permissions.append(perm_name)
    
    issue_counts["permissions"] = len(permissions)

    if permissions:
        for p in sorted(permissions):
            print_info(f"- {p}")
    else:
        print_success("No 'uses-permission' declarations found.")

    print_header("Scanning Application Configurations")
    app_node = axml_obj.find("application")
    if app_node is not None:
        debuggable = app_node.get(NS_ANDROID + 'debuggable')
        if debuggable == 'true':
            print_warning("Application is in debuggable mode (android:debuggable='true')")
            issue_counts["debuggable"] = 1
        else:
            print_success("Application is not in debuggable mode.")
        
        allow_backup = app_node.get(NS_ANDROID + 'allowBackup')
        if allow_backup == 'false':
            print_success("Application data backup is disabled (android:allowBackup='false').")
        else:
            print_warning("Application data backup is allowed (android:allowBackup is not 'false')")
            issue_counts["allow_backup"] = 1

    main_activity_nodes = axml_obj.xpath(
        '//activity[intent-filter/action[@android:name="android.intent.action.MAIN"] and intent-filter/category[@android:name="android.intent.category.LAUNCHER"]]',
        namespaces=nsmap
    )
    main_activity_name = main_activity_nodes[0].get(NS_ANDROID + 'name') if main_activity_nodes else None

    total_insecure_components = 0
    for tag in ['activity', 'service', 'receiver', 'provider']:
        print_header(f"Scanning <{tag}> Components")
        components = app_node.findall(tag) if app_node is not None else []
        if not components:
            print_success(f"No <{tag}> components found.")
            continue

        found_issues = False
        for comp in components:
            name = comp.get(NS_ANDROID + 'name')
            exported = comp.get(NS_ANDROID + 'exported')
            permission = comp.get(NS_ANDROID + 'permission')
            
            has_intent_filter = True if comp.find('intent-filter') is not None else False

            is_exported = False
            reason = ""
            if exported == 'true':
                is_exported = True
                reason = "Reason: 'exported' is set to 'true'."
            elif exported is None and has_intent_filter:
                is_exported = True
                reason = "Reason: 'exported' is not set and an <intent-filter> is present, defaulting to exported."

            is_launcher = (name == main_activity_name)

            if is_exported and not permission and not is_launcher:
                found_issues = True
                total_insecure_components += 1
                print_warning(f"Insecure exported component found: {name}")
                print_info(f"Details: This <{tag}> is exported but not protected by a permission.")
                print_info(reason)
        
        if not found_issues:
            print_success(f"No insecurely exported <{tag}> components found.")
    
    issue_counts["insecure_components"] = total_insecure_components
    return issue_counts

def analyze_resources_arsc(apk_path):
    issue_counts = {"urls": 0, "ips": 0}
    print_header("Scanning resources.arsc for URLs and IPs")
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            if 'resources.arsc' not in apk_zip.namelist():
                print_success("resources.arsc not found in APK.")
                return {}
            
            arsc_data = apk_zip.read('resources.arsc')
            arsc_parser = ARSCParser(arsc_data)

            if arsc_parser.stringpool_main is None:
                print_success("Main string pool not found in resources.arsc.")
                return {}
                
            all_strings = arsc_parser.stringpool_main

            if not all_strings:
                print_success("No strings found in the main string pool of resources.arsc.")
                return {}

            found_urls = set()
            found_ips = set()

            url_pattern = r'https?://.*'
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b'

            for s in all_strings:
                if s:
                    found_urls.update(re.findall(url_pattern, s, re.IGNORECASE))
                    found_ips.update(re.findall(ip_pattern, s))

            issue_counts["urls"] = len(found_urls)
            issue_counts["ips"] = len(found_ips)

            if found_urls:
                print_warning("Potential URLs found in resources.arsc string pool:")
                for url in sorted(list(found_urls)):
                    print_info(f"{url}")
            else:
                print_success("No URLs found in resources.arsc string pool.")

            if found_ips:
                print_warning("Potential IP addresses found in resources.arsc string pool:")
                for ip in sorted(list(found_ips)):
                    print_info(f"{ip}")
            else:
                print_success("No IP addresses found in resources.arsc string pool.")
        
        return issue_counts

    except Exception as e:
        print(f"An error occurred while processing resources.arsc: {e}")
        return {}

def analyze_signature_and_hashes(apk_path):
    print_header("Signature and Certificate Analysis")
    try:
        apk = APK(apk_path)
        
        if not apk.is_signed():
            print_warning("APK is not signed.")
            return

        print_info(f"App Signed: {'Yes' if apk.is_signed() else 'No'}")
        print_info(f"V1 Signature (JAR): {'Yes' if apk.is_signed_v1() else 'No'}")
        print_info(f"V2 Signature (APK): {'Yes' if apk.is_signed_v2() else 'No'}")
        print_info(f"V3 Signature (APK): {'Yes' if apk.is_signed_v3() else 'No'}")
        print_info(f"V4 Signature (APK): No")

        certs = apk.get_certificates()
        if not certs:
            print_warning("No certificates found in the signature.")
            return

        print_info(f"\nFound {len(certs)} unique certificate(s):")

        for i, cert in enumerate(certs):
            print("\n    " + "-"*52)
            print(f"    Certificate #{i+1}:")
            print("    " + "-"*52)
            
            subject_str = get_certificate_name_string(cert.subject, short=True)
            issuer_str = get_certificate_name_string(cert.issuer, short=True)
            tbs_cert = cert['tbs_certificate']
            validity = tbs_cert['validity']

            print_info(f"Subject: {subject_str}")
            print_info(f"Issuer: {issuer_str}")
            print_info(f"Serial Number: {hex(cert.serial_number)}")
            print_info(f"Valid From: {validity['not_before'].native}")
            print_info(f"Valid Until: {validity['not_after'].native}")
            print_info(f"Signature Algorithm: {cert.signature_algo}")
            print_info(f"Hash Algorithm Used: {cert.hash_algo}")
            
            pub_key = cert.public_key
            print_info(f"Public Key Algorithm: {pub_key.algorithm}")
            print_info(f"Bit Size: {pub_key.bit_size}")

        with open(apk_path, 'rb') as f:
            file_data = f.read()
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha1_hash = hashlib.sha1(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            sha512_hash = hashlib.sha512(file_data).hexdigest()

        print("\n    " + "-"*52)
        print("    File Hashes:")
        print("    " + "-"*52)
        print_info(f"MD5:    {md5_hash}")
        print_info(f"SHA1:   {sha1_hash}")
        print_info(f"SHA256: {sha256_hash}")
        print_info(f"SHA512: {sha512_hash}")

    except Exception as e:
        print(f"An error occurred during signature analysis: {e}")


def main(apk_path):
    axml_obj = None
    try:
        with zipfile.ZipFile(apk_path, 'r') as apk_zip:
            manifest_data = apk_zip.read('AndroidManifest.xml')
            axml_obj = AXMLPrinter(manifest_data).get_xml_obj()
            package = axml_obj.get('package')
            version_name = axml_obj.get(NS_ANDROID + 'versionName')
            print_header(f"Starting analysis for package: {package} (Version: {version_name})")

            analyze_signature_and_hashes(apk_path)
    except Exception:
        print_header(f"Starting analysis for: {apk_path}")

    manifest_issues = analyze_manifest(apk_path) or {}
    arsc_issues = analyze_resources_arsc(apk_path) or {}

    total_issues = {**manifest_issues, **arsc_issues}

    print_header("Scan Summary")
    
    total_permissions = total_issues.get("permissions", 0)
    insecure_components = total_issues.get("insecure_components", 0)
    is_debuggable = total_issues.get("debuggable", 0)
    is_allow_backup = total_issues.get("allow_backup", 0)
    found_urls = total_issues.get("urls", 0)
    found_ips = total_issues.get("ips", 0)

    print_info(f"Total permissions declared: {total_permissions}")
    print_info(f"Insecure exported components: {insecure_components}")
    print_info(f"Debuggable mode enabled: {'Yes' if is_debuggable > 0 else 'No'}")
    print_info(f"Data backup enabled: {'Yes' if is_allow_backup > 0 else 'No'}")
    print_info(f"URLs found in resources: {found_urls}")
    print_info(f"IP addresses found in resources: {found_ips}")

    total_warnings = insecure_components + is_debuggable + is_allow_backup + found_urls + found_ips
    
    print("\n------------------------------------------------------------")
    if total_warnings > 0:
        print(f"[*] Conclusion: Found {total_warnings} potential security risks.")
    else:
        print("[*] Conclusion: No high-level security risks were found.")
    print("------------------------------------------------------------")

    return axml_obj

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A script to scan Android APK files for common vulnerabilities using pyaxmlparser.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("apk_path", help="Path to the APK file to be analyzed.")
    parser.add_argument("s", help="adb device id")
    args = parser.parse_args()
    
    axml_obj = main(args.apk_path)

    import os
    os.system(f'./ApkCheckPack* -f {args.apk_path}')

    # panda or frida-dexdump
    print_header("Dynamic Analysis:")
    try:
        os.system(f'adb -s {args.s} push ./panda-dex-dumper /data/local/tmp')
        os.system(f'adb -s {args.s} shell "chmod +x /data/local/tmp/panda-dex-dumper"')
        os.system(f'adb -s {args.s} shell "cd /data/local/tmp/ && /data/local/tmp/panda-dex-dumper -p \$(pidof {axml_obj.get('package')}) &>/dev/null"')
        os.system(f'adb -s {args.s} pull /data/local/tmp/panda .')

        os.system('mkdir ./jar-result')
        os.system('cd ./jar-result;for i in `ls ../panda/`;do ../dex-tools-v*/d2j-dex2jar.sh ../panda/$i -f -n --skip-exceptions &>/dev/null;done')

        # jar to java class
        os.system('jadx -d ./classes ./jar-result/dex_*.jar &>/dev/null')


        print_header("SQL query:")
        os.system("grep -iE 'rawQuery\\(\"|Query\\(\"|execSQL\\(\"' -R ./classes/sources")

        print_header("Root path detection:")
        os.system("grep -iE '/cache/.disable_magisk|/cache/magisk.log|/cache/su|/data/adb/ksu|/data/adb/ksud|/data/adb/magisk|/data/adb/magisk.db|/data/adb/magisk.img|/data/adb/magisk_simple|/data/local/bin/su|/data/local/su|/data/local/xbin/su|/data/su|/dev/.magisk.unblock|/dev/com.koushikdutta.superuser.daemon/|/dev/su|/init.magisk.rc|/sbin/.magisk|/sbin/su|/su/bin/su|/system/app/Kinguser.apk|/system/app/Superuser.apk|/system/bin/.ext/su|/system/bin/failsafe/su|/system/bin/su|/system/etc/init.d/99SuperSUDaemon|/system/sbin/su|/system/sd/xbin/su|/system/usr/we-need-root/su|/system/xbin/busybox|/system/xbin/daemonsu|/system/xbin/ku.sud|/system/xbin/su|/vendor/bin/su|Kinguser.apk|Superuser.apk|/system/xbin/|/vendor/bin/' -R ./classes/sources")

        print_header("Root package name detection:")
        os.system("grep -iE 'com.chelpus.lackypatch|com.dimonvideo.luckypatcher|com.koushikdutta.rommanager|com.koushikdutta.rommanager.license|com.koushikdutta.superuser|com.noshufou.android.su|com.noshufou.android.su.elite|com.ramdroid.appquarantine|com.ramdroid.appquarantinepro|com.thirdparty.superuser|com.topjohnwu.magisk|com.yellowes.su|eu.chainfire.supersu|me.weishu.kernelsu|com.kingroot.kinguser|com.kingoapp.root|me.phh.superuser|com.apusapps.browser.module.root|io.github.vvb2060.magisk|com.topjohnwu.magisk.pro|de.robv.android.xposed.installer|org.meowcat.edxposed.manager|me.weishu.exp|com.speedsoftware.rootexplorer|com.keramidas.TitaniumBackup|com.joeykrim.rootcheck|com.device.report|com.qihoo.root|com.dianxinos.optimizer.duplay|com.geohot.towelroot|com.zachspong.temprootremove|com.riru.core|com.github.topjohnwu.magisk.installer|com.alephzain.framaroot|org.chainfire.internet' -R ./classes/sources")

        print_header("Emulator Detection:")
        os.system("grep -iE 'tel:123456|test-keys|goldfish|android-test|/dev/socket/qemud|/dev/qemu_pipe|/dev/qemu_trace|ro.kernel.qemu|generic_x86|emulator|ro.boot.virtual|ro.cloudbuild.software|ro.secureboot.lockstate|ro.cpu.virtual|Build.PRODUCT=sdk_google|Build.MODEL=Android SDK built|Build.HARDWARE=goldfish|Build.FINGERPRINT=generic|Sensor.TYPE_SIGNIFICANT_MOTION|Sensor.TYPE_STEP_COUNTER|Sensor.TYPE_HEART_RATE|10.0.2.15|eth0|dns.google|debug.stagefright.ccode|ro.kernel.android.checkjni|ro.boot.selinux=disabled|hasQemuSocket|hasQemuPipe|getEmulatorQEMUKernel|Landroid/os/SystemProperties;->get(Ljava/lang/String;)' -R ./classes/sources")

        print_header("Anti-Debugging Detection:")
        os.system("grep -iE 'checkFridaRunningProcesses|checkRunningProcesses|checkRunningServices|treadCpuTimeNanos|TamperingWithJavaRuntime|com.android.internal.os.ZygoteInit|com.saurik.substrate.MS$2|de.robv.android.xposed.XposedBridge|detectBypassSSL|Landroid/os/Debug;->isDebuggerConnected()Z|:27042|:23946|frida-gadget|libfrida.so|XposedBridge.jar|EdXposed|frida-server|android_server|gdbserver|ro.debuggable|service.adb.root|XposedInstaller|Magisk|LSPosed|ptrace|/proc/self/status|libsubstrate.so|com.saurik.substrate|sslunpinning|JustTrustMe|/data/data/de.robv.android.xposed.installer/conf/modules.list' -R ./classes/sources")

    except:
        pass
