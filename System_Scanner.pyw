import eel
import platform
import psutil
import wmi
import winreg
import sys
import os
import subprocess
import urllib.request
import json
import glob
import hashlib
import time
from datetime import datetime
import re as _re
import socket

# Optional dependency: pywin32 for EXE version info
try:
    import win32api  # type: ignore
    PYWIN32_AVAILABLE = True
except Exception:
    PYWIN32_AVAILABLE = False

def resource_path(relative_path):
    try:
        base = sys._MEIPASS
    except:
        base = os.path.abspath(".")
    return os.path.join(base, relative_path)

html_file = resource_path("web/index.html")

eel.init('web')

VERSION = "1.1"

def _progress(msg, pct):
    """Send scan progress update to the UI (non-critical)."""
    try:
        eel.update_scan_progress(msg, pct)
    except Exception:
        pass

# Fallback static versions (used if live fetch fails)
LATEST_BROWSER_VERSIONS = {
    "Google Chrome": "145.0.7632.77",
    "Microsoft Edge": "145.0.3800.70",
    "Mozilla Firefox": "147.0.4",
    "Firefox Developer Edition": "148.0b15",
    "Brave": "1.87.190",
    "Opera": "127.0.5778.64",
    "Opera GX": "127.0.5778.67",
    "Vivaldi": "7.8",
    "Arc": "1.92.0",
    "Zen": "1.18.10b",
}

def get_ps(cmd):
    try:
        return subprocess.check_output(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            timeout=20, stderr=subprocess.STDOUT, shell=True
        ).decode().strip()
    except Exception:
        return "Not Detected"


def ps_first(commands):
    """Try a list of PowerShell commands, returning the first non-empty result."""
    for c in commands:
        out = get_ps(c)
        if out and out not in ("Not Detected", "", None):
            return out
    return "Not Detected"


def get_exe_version(path):
    """Return ProductVersion for a Windows executable path using pywin32 if available, else fallback.
    Returns string like '123.0.6312.86' or '' if not available.
    """
    if not path or not os.path.exists(path):
        return ""
    if PYWIN32_AVAILABLE:
        try:
            info = win32api.GetFileVersionInfo(path, '\\')
            ms = info['FileVersionMS']
            ls = info['FileVersionLS']
            return f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
        except Exception:
            pass
    # PS fallback
    try:
        v = get_ps(f"(Get-Item '{path}').VersionInfo.ProductVersion")
        if v and v != "Not Detected":
            return v
    except Exception:
        pass
    return ""


def read_registry_value(hive, key_path, value_name):
    try:
        with winreg.OpenKey(hive, key_path) as k:
            v, _ = winreg.QueryValueEx(k, value_name)
            return v
    except Exception:
        return None


def enumerate_uninstall_entries():
    """Yield dicts of uninstall entries from common registry locations."""
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, base in roots:
        try:
            with winreg.OpenKey(hive, base) as key:
                n = winreg.QueryInfoKey(key)[0]
                for i in range(n):
                    try:
                        sub_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, sub_name) as sub:
                            entry = {}
                            for field in ("DisplayName", "DisplayVersion", "Publisher", "InstallLocation", "DisplayIcon", "UninstallString", "EstimatedSize", "SystemComponent"):
                                try:
                                    entry[field] = winreg.QueryValueEx(sub, field)[0]
                                except Exception:
                                    entry[field] = ""
                            if entry.get("DisplayName"):
                                yield entry
                    except Exception:
                        continue
        except Exception:
            continue


# Live browser version cache (refreshed once per session)
_DYNAMIC_BROWSER_VERSIONS = {}
_LAST_FETCH_TS = 0


def fetch_latest_browser_versions(force=False):
    global _DYNAMIC_BROWSER_VERSIONS, _LAST_FETCH_TS
    now = time.time()
    if not force and _DYNAMIC_BROWSER_VERSIONS and now - _LAST_FETCH_TS < 60 * 30:  # 30 min
        return _DYNAMIC_BROWSER_VERSIONS
    versions = {}
    # Chrome stable
    try:
        with urllib.request.urlopen("https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions", timeout=10) as r:
            data = json.loads(r.read().decode())
            if isinstance(data, dict) and 'versions' in data and data['versions']:
                latest = data['versions'][0]['version']
            elif isinstance(data, list) and data:
                latest = data[0].get('version')
            else:
                latest = None
            if latest:
                versions['Google Chrome'] = int(str(latest).split('.')[0])
    except Exception:
        pass
    # Firefox
    try:
        with urllib.request.urlopen("https://product-details.mozilla.org/1.0/firefox_versions.json", timeout=10) as r:
            data = json.loads(r.read().decode())
            v = data.get('LATEST_FIREFOX_VERSION') or data.get('FIREFOX_NIGHTLY') or ''
            if v:
                versions['Mozilla Firefox'] = int(str(v).split('.')[0])
    except Exception:
        pass
    # Edge
    try:
        with urllib.request.urlopen("https://edgeupdates.microsoft.com/api/products", timeout=10) as r:
            data = json.loads(r.read().decode())
            for prod in data:
                if prod.get('Product') == 'Stable':
                    # Picks Windows entry
                    for rel in prod.get('Releases', []):
                        v = rel.get('ProductVersion')
                        if v:
                            versions['Microsoft Edge'] = int(str(v).split('.')[0])
                            raise StopIteration
    except StopIteration:
        pass
    except Exception:
        pass
    # Brave
    try:
        with urllib.request.urlopen("https://api.github.com/repos/brave/brave-browser/releases/latest", timeout=10) as r:
            data = json.loads(r.read().decode())
            tag = data.get('tag_name', '').lstrip('v')
            if tag:
                versions['Brave'] = int(tag.split('.')[0])
    except Exception:
        pass
    # Opera - fallback to heuristics (Chrome major - 17 approx) if unknown
    if 'Google Chrome' in versions and 'Opera' not in versions:
        try:
            versions['Opera'] = max(1, versions['Google Chrome'] - 17)
            versions['Opera GX'] = versions['Opera']
        except Exception:
            pass
    # Vivaldi (uses own numbering, expose as major of first component when available via update feed)
    try:
        with urllib.request.urlopen("https://update.vivaldi.com/update/1.0/public/appcast/win/stable/appcast.xml", timeout=10) as r:
            xml = r.read().decode(errors='ignore')
            import re
            m = re.search(r'version="([\d\.]+)"', xml)
            if m:
                versions['Vivaldi'] = int(m.group(1).split('.')[0])
    except Exception:
        pass

    if versions:
        _DYNAMIC_BROWSER_VERSIONS = versions
        _LAST_FETCH_TS = now
    return _DYNAMIC_BROWSER_VERSIONS

def _get_latest_versions():
    live = fetch_latest_browser_versions(force=False)
    merged = dict(LATEST_BROWSER_VERSIONS)
    for k, v in live.items():
        if isinstance(v, int):
            merged[k] = v
    return merged

@eel.expose
def check_for_updates():
    """Compare local VERSION against the latest GitHub release tag."""
    api_url = "https://api.github.com/repos/ImmaGundam/WebGeeks-SystemShield/releases/latest"
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "SystemShield"})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            latest_version = data['tag_name'].lstrip('v')
            # Tuple comparison handles 1.1 vs 1.2 and 1.1.1 vs 1.1.2
            local_parts = tuple(int(x) for x in VERSION.split('.'))
            remote_parts = tuple(int(x) for x in latest_version.split('.'))
            if remote_parts > local_parts:
                return {"status": "update_available", "version": latest_version, "current": VERSION}
            return {"status": "up_to_date", "version": VERSION}
    except Exception:
        return {"status": "error", "version": VERSION}

@eel.expose
def perform_scan():
    try:
        _progress("Starting system scan...", 0)

        results = {}
        risk_count = 0
        caution_count = 0

        # Ensure latest browser versions are loaded (non-blocking if offline)
        _progress("Checking browser versions...", 5)
        _ = _get_latest_versions()

        # ---------------- BASIC OS ----------------
        _progress("Collecting OS information...", 10)
        results['user'] = os.getlogin()
        results['os_name'] = f"{platform.system()} {platform.release()}"

        # Get detailed Windows info
        results['windows_version'] = get_ps("(Get-CimInstance Win32_OperatingSystem).Version")
        results['windows_build'] = get_ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber")
        results['os_caption'] = get_ps("(Get-CimInstance Win32_OperatingSystem).Caption")
        results['service_pack'] = get_ps("(Get-ComputerInfo).OsHardwareAbstractionLayer")

# ---------------- SECURITY BASELINE ----------------
        _progress("Checking security baseline...", 20)
        sb_status = ps_first([
            "Confirm-SecureBootUEFI",
            "Write-Output 'Unsupported'"  # XP/Legacy fallback
        ])
        tpm_status = ps_first([
            "(Get-Tpm).TpmPresent",
            "(Get-WmiObject -Namespace root/cimv2/Security/MicrosoftTpm -Class Win32_Tpm).IsEnabled_InitialValue",
            "Write-Output 'False'"
        ])
        vbs_status = ps_first([
            "(Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard).VirtualizationBasedSecurityStatus",
            "Write-Output '0'"
        ])

        results['os_security'] = {
            "secure_boot": "Enabled" if "True" in sb_status else "Disabled/Unsupported",
            "tpm": "Present (v2.0)" if "True" in tpm_status else "Not Found",
            "vbs": "Running" if vbs_status == "2" else "Off"
        }

        if "True" not in sb_status: risk_count += 1
        if "True" not in tpm_status: risk_count += 1
        if vbs_status != "2": risk_count += 1

# ---------------- DRIVE ENCRYPTION ----------------
        _progress("Checking drive encryption...", 30)
        try:
            bitlocker_status = ps_first([
                "Get-BitLockerVolume | Select-Object -ExpandProperty ProtectionStatus",
                "(manage-bde -status C:) | Select-String 'Percentage Encrypted' | ForEach-Object { ($_ -split ':')[1].Trim() }"
            ])
            enc = False
            if bitlocker_status and bitlocker_status != "Not Detected":
                if any(x in bitlocker_status for x in ["1", "100%", "Encrypted"]):
                    enc = True
            results['drive_encryption'] = "Encrypted" if enc else "Not Encrypted"
            # Get encryption method details
            enc_method = "Unknown"
            enc_version = ""
            if enc:
                try:
                    enc_method_raw = ps_first([
                        "manage-bde -status C: 2>$null | Select-String 'Encryption Method' | ForEach-Object { ($_ -split ':\s*',2)[1].Trim() }",
                        "try{(Get-BitLockerVolume -MountPoint C: -ErrorAction Stop).EncryptionMethod}catch{}",
                    ])
                    if enc_method_raw and enc_method_raw != "Not Detected" and len(enc_method_raw) < 80 and "Exception" not in enc_method_raw and "Access denied" not in enc_method_raw:
                        enc_method = enc_method_raw
                    enc_ver_raw = ps_first([
                        "manage-bde -status C: 2>$null | Select-String 'Version' | Select-Object -First 1 | ForEach-Object { ($_ -split ':\s*',2)[1].Trim() }",
                    ])
                    if enc_ver_raw and enc_ver_raw != "Not Detected" and len(enc_ver_raw) < 80 and "Exception" not in enc_ver_raw:
                        enc_version = enc_ver_raw
                except Exception:
                    pass
            # Fallback: determine type from OS edition if method still unknown
            if enc and enc_method == "Unknown":
                try:
                    os_sku = get_ps("(Get-CimInstance Win32_OperatingSystem).OperatingSystemSKU")
                    home_skus = ['4', '5', '98', '100', '101']  # Home edition SKUs
                    if os_sku in home_skus:
                        enc_method = "Device Encryption"
                        enc_version = "XTS-AES 128-bit"
                    else:
                        enc_method = "BitLocker"
                except Exception:
                    pass
            # Final fallback: check registry for policy encryption method
            if enc and enc_method in ("Unknown", "BitLocker"):
                try:
                    policy_method = get_ps(
                        "Get-ItemPropertyValue -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE' "
                        "-Name 'EncryptionMethodWithXtsOs' -ErrorAction SilentlyContinue"
                    )
                    method_map = {'3': 'AES-CBC 128-bit', '4': 'AES-CBC 256-bit',
                                  '6': 'XTS-AES 128-bit', '7': 'XTS-AES 256-bit'}
                    if policy_method in method_map:
                        enc_version = method_map[policy_method]
                except Exception:
                    pass
            results['encryption_method'] = enc_method
            results['encryption_version'] = enc_version
            if not enc:
                risk_count += 1
        except Exception:
            results['drive_encryption'] = "Unknown"
            results['encryption_method'] = "Unknown"
            results['encryption_version'] = ""

        # ---------------- PASSWORD & LOCK SCREEN ----------------
        _progress("Checking password security...", 40)
        # Check if password is set - use multiple methods for compatibility
        # Method 1: Check PasswordLastSet (if set, password exists)
        pwd_last_set = get_ps("(Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue).PasswordLastSet")
        # Method 2: Use net user as fallback (works on Win10/11)
        net_user_output = get_ps("net user $env:USERNAME | Select-String 'Password required' | ForEach-Object { $_.Line }")
        # Method 3: Check if blank password is allowed via registry
        limit_blank = get_ps("Get-ItemPropertyValue -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue")
        
        # Determine if password is set
        password_set = False
        if pwd_last_set and pwd_last_set != "Not Detected" and pwd_last_set.strip() != "":
            # PasswordLastSet has a value means password was set at some point
            password_set = True
        elif "Yes" in net_user_output:
            # "Password required: Yes" from net user
            password_set = True
        elif limit_blank == "1":
            # If blank passwords are limited and user can log in, they have a password
            password_set = True
        
        # Check screen saver password protection
        screensaver_secure = get_ps("Get-ItemPropertyValue -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue")
        # Check lock screen timeout (AC power)
        lock_timeout = get_ps("powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK | Select-String 'Current AC Power Setting Index' | ForEach-Object { ($_ -split ':')[1].Trim() }")
        # Check sleep timeout
        sleep_timeout = get_ps("powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | Select-String 'Current AC Power Setting Index' | ForEach-Object { ($_ -split ':')[1].Trim() }")
        
        lock_enabled = lock_timeout not in ["0x00000000", "0", "", "Not Detected"] or screensaver_secure == "1"
        sleep_enabled = sleep_timeout not in ["0x00000000", "0", "", "Not Detected"]
        
        results['lock_security'] = {
            "password_set": "Yes" if password_set else "No",
            "lock_screen": "Enabled" if lock_enabled else "Disabled",
            "sleep_timeout": "Enabled" if sleep_enabled else "Disabled"
        }
        
        if not password_set: 
            risk_count += 1
        if not lock_enabled and password_set:
            caution_count += 1
        elif not lock_enabled:
            caution_count += 1
        if not sleep_enabled:
            caution_count += 1

# ---------------- USER SECURITY ----------------
        _progress("Checking user security settings...", 50)
        is_admin = "True" in get_ps("([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')")
        uac_enabled = ps_first([
            "(Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA).EnableLUA",
            "Write-Output 1"  # Assume enabled if not found (compat)
        ])
        
        # Check account type (Microsoft vs Local)
        account_type_check = ps_first([
            "(Get-CimInstance Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).AccountType",
            "Write-Output ''"
        ])
        ms_account = ps_first([
            "Get-ItemPropertyValue -Path 'HKCU:\\Software\\Microsoft\\IdentityStore\\Cache\\*\\IdentityCache\\*' -Name UserName -ErrorAction SilentlyContinue 2>$null | Select-Object -First 1",
            "Write-Output ''"
        ])
        
        if "@" in ms_account:
            account_type = "Microsoft Account"
        else:
            account_type = "Local Account"

        results['user_security'] = {
            "is_admin": "Yes" if is_admin else "No",
            "uac": "Enabled" if "1" in uac_enabled else "Disabled",
            "account_type": account_type
        }

        if is_admin: risk_count += 1
        if "1" not in uac_enabled: risk_count += 1

        # ---------------- ANTIVIRUS ----------------
        _progress("Checking antivirus status...", 60)
        av_raw = get_ps("Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName")
        av_list = [line.strip() for line in av_raw.split("\n") if line.strip() and line.strip().lower() not in ['displayname', '----------', '-----------', '------------', 'not detected', '']]
        
        # Check Windows Defender status separately
        defender_status = get_ps("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled")
        if "True" in defender_status and "Windows Defender" not in str(av_list):
            av_list.append("Windows Defender")
        
        # Check for Malwarebytes specifically (free version may not register in SecurityCenter2)
        mb_in_av = any('malwarebytes' in av.lower() for av in av_list)
        if not mb_in_av:
            mb_installed = False
            mb_reg_paths = [r"SOFTWARE\Malwarebytes", r"SOFTWARE\Malwarebytes' Anti-Malware"]
            mb_exe_paths = [
                r"C:\Program Files\Malwarebytes\Anti-Malware\mbam.exe",
                r"C:\Program Files (x86)\Malwarebytes\Anti-Malware\mbam.exe",
            ]
            for rp in mb_reg_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rp):
                        mb_installed = True
                        break
                except Exception:
                    pass
            if not mb_installed:
                for ep in mb_exe_paths:
                    if os.path.exists(ep):
                        mb_installed = True
                        break
            if mb_installed:
                av_list.append("Malwarebytes (Free)")

        if not av_list:
            risk_count += 1
        results['av_details'] = av_list

# ---------------- FIREWALL ----------------
        _progress("Checking firewall configuration...", 70)
        fw_products = []
        
        # Check Windows Firewall profiles with fallback to netsh
        fw_domain = ps_first([
            "(Get-NetFirewallProfile -Name Domain).Enabled",
            "(netsh advfirewall show domainprofile | Select-String 'State') -match 'ON'"
        ])
        fw_private = ps_first([
            "(Get-NetFirewallProfile -Name Private).Enabled",
            "(netsh advfirewall show privateprofile | Select-String 'State') -match 'ON'"
        ])
        fw_public = ps_first([
            "(Get-NetFirewallProfile -Name Public).Enabled",
            "(netsh advfirewall show publicprofile | Select-String 'State') -match 'ON'"
        ])
        
        windows_fw_enabled = "True" in fw_domain or "True" in fw_private or "True" in fw_public
        if windows_fw_enabled:
            profiles_on = []
            if "True" in fw_domain: profiles_on.append("Domain")
            if "True" in fw_private: profiles_on.append("Private")
            if "True" in fw_public: profiles_on.append("Public")
            fw_products.append({"name": "Windows Firewall", "profiles": profiles_on, "status": "Enabled"})
        
        # Check third-party firewalls from SecurityCenter2
        fw_raw = get_ps("Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName FirewallProduct | Select-Object -ExpandProperty displayName")
        third_party = [line.strip() for line in fw_raw.split("\n") if line.strip() and line.strip().lower() not in ['displayname', '----------', '-----------', '------------', 'not detected', 'windows firewall', '']]
        
        for fw in third_party:
            fw_products.append({"name": fw, "profiles": [], "status": "Active"})
        
        results['fw_details'] = {
            "products": fw_products,
            "windows_fw_enabled": windows_fw_enabled,
            "third_party_count": len(third_party)
        }
        
        if not windows_fw_enabled and len(third_party) == 0:
            risk_count += 1

        # ---------------- BROWSERS ----------------
        _progress("Detecting browsers and versions...", 75)
        browsers = []
        found_browsers = set()
        
        # Browser metadata: engine type and discontinued status
        BROWSER_META = {
            "Google Chrome": {"engine": "Chromium", "discontinued": False},
            "Microsoft Edge": {"engine": "Chromium", "discontinued": False},
            "Mozilla Firefox": {"engine": "Gecko", "discontinued": False},
            "Brave": {"engine": "Chromium", "discontinued": False},
            "Opera": {"engine": "Chromium", "discontinued": False},
            "Opera GX": {"engine": "Chromium", "discontinued": False},
            "Vivaldi": {"engine": "Chromium", "discontinued": False},
            "Arc": {"engine": "Chromium", "discontinued": False},
            "Chromium": {"engine": "Chromium", "discontinued": False},
            "SRWare Iron": {"engine": "Chromium", "discontinued": False},
            "Yandex Browser": {"engine": "Chromium", "discontinued": False},
            "UC Browser": {"engine": "Chromium", "discontinued": True},
            "Avast Secure Browser": {"engine": "Chromium", "discontinued": False},
            "AVG Secure Browser": {"engine": "Chromium", "discontinued": False},
            "Torch": {"engine": "Chromium", "discontinued": True},
            "Slimjet": {"engine": "Chromium", "discontinued": False},
            "Comodo Dragon": {"engine": "Chromium", "discontinued": False},
            "CoolNovo": {"engine": "Chromium", "discontinued": True},
            "Naver Whale": {"engine": "Chromium", "discontinued": False},
            "Iridium": {"engine": "Chromium", "discontinued": False},
            "Epic Privacy Browser": {"engine": "Chromium", "discontinued": False},
            "CentBrowser": {"engine": "Chromium", "discontinued": False},
            "360 Browser": {"engine": "Chromium", "discontinued": False},
            "Coc Coc": {"engine": "Chromium", "discontinued": False},
            "Firefox Developer Edition": {"engine": "Gecko", "discontinued": False},
            "Waterfox": {"engine": "Gecko", "discontinued": False},
            "LibreWolf": {"engine": "Gecko", "discontinued": False},
            "Zen Browser": {"engine": "Gecko", "discontinued": False},
            "Tor Browser": {"engine": "Gecko", "discontinued": False},
            "Pale Moon": {"engine": "Gecko", "discontinued": False},
            "SeaMonkey": {"engine": "Gecko", "discontinued": False},
            "K-Meleon": {"engine": "Gecko", "discontinued": False},
            "Basilisk": {"engine": "Gecko", "discontinued": False},
            "IceCat": {"engine": "Gecko", "discontinued": False},
            "Internet Explorer": {"engine": "Trident", "discontinued": True},
            "Safari": {"engine": "WebKit", "discontinued": True},
            "Avant Browser": {"engine": "Other", "discontinued": True},
            "Lunascape": {"engine": "Other", "discontinued": True},
            "Flock": {"engine": "Other", "discontinued": True},
            "RockMelt": {"engine": "Other", "discontinued": True},
            "Midori": {"engine": "Other", "discontinued": True},
            "Maxthon": {"engine": "Chromium", "discontinued": False},
        }

        # Registry paths for browser detection (expanded)
        browser_registry = [
            ("Google Chrome", r"Software\Google\Chrome\BLBeacon", "version", winreg.HKEY_CURRENT_USER),
            ("Google Chrome", r"SOFTWARE\Google\Chrome\BLBeacon", "version", winreg.HKEY_LOCAL_MACHINE),
            ("Microsoft Edge", r"Software\Microsoft\Edge\BLBeacon", "version", winreg.HKEY_CURRENT_USER),
            ("Microsoft Edge", r"SOFTWARE\Microsoft\Edge\BLBeacon", "version", winreg.HKEY_LOCAL_MACHINE),
            ("Mozilla Firefox", r"SOFTWARE\Mozilla\Mozilla Firefox", "CurrentVersion", winreg.HKEY_LOCAL_MACHINE),
            ("Firefox Developer Edition", r"SOFTWARE\Mozilla\Firefox Developer Edition", "CurrentVersion", winreg.HKEY_LOCAL_MACHINE),
            ("Zen Browser", r"SOFTWARE\Mozilla\Zen Browser", "CurrentVersion", winreg.HKEY_LOCAL_MACHINE),
            ("Brave", r"Software\BraveSoftware\Brave-Browser\BLBeacon", "version", winreg.HKEY_CURRENT_USER),
            ("Brave", r"SOFTWARE\BraveSoftware\Brave-Browser\BLBeacon", "version", winreg.HKEY_LOCAL_MACHINE),
            ("Opera", r"Software\Opera Software", "Last Stable Install Path", winreg.HKEY_CURRENT_USER),
            ("Opera GX", r"Software\Opera Software\Opera GX Stable", "Last Stable Install Path", winreg.HKEY_CURRENT_USER),
            ("Vivaldi", r"Software\Vivaldi", "Version", winreg.HKEY_CURRENT_USER),
            ("Arc", r"Software\Arc\Arc", "Version", winreg.HKEY_CURRENT_USER),
            ("Yandex Browser", r"Software\Yandex\YandexBrowser\BLBeacon", "version", winreg.HKEY_CURRENT_USER),
            ("Avast Secure Browser", r"Software\AVAST Software\Browser\BLBeacon", "version", winreg.HKEY_CURRENT_USER),
            ("AVG Secure Browser", r"Software\AVG\Browser\BLBeacon", "version", winreg.HKEY_CURRENT_USER),
            ("Internet Explorer", r"SOFTWARE\Microsoft\Internet Explorer", "svcVersion", winreg.HKEY_LOCAL_MACHINE),
            ("Waterfox", r"SOFTWARE\Mozilla\Waterfox", "CurrentVersion", winreg.HKEY_LOCAL_MACHINE),
        ]
        
        for name, path, value_name, hive in browser_registry:
            if name in found_browsers:
                continue
            try:
                with winreg.OpenKey(hive, path) as key:
                    v, _ = winreg.QueryValueEx(key, value_name)
                    if v:
                        meta = BROWSER_META.get(name, {"engine": "Unknown", "discontinued": False})
                        browsers.append({"name": name, "version": str(v), "engine": meta["engine"], "discontinued": meta["discontinued"]})
                        found_browsers.add(name)
            except Exception:
                continue
        
        # Check common browser executables for versions we might have missed (expanded ~40 browsers)
        browser_exe_paths = [
            ("Google Chrome", [r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]),
            ("Mozilla Firefox", [r"C:\Program Files\Mozilla Firefox\firefox.exe", r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"]),
            ("Brave", [r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"]),
            ("Opera", [r"C:\Program Files\Opera\launcher.exe", os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera\launcher.exe")]),
            ("Opera GX", [os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera GX\launcher.exe")]),
            ("Vivaldi", [r"C:\Program Files\Vivaldi\Application\vivaldi.exe", os.path.expandvars(r"%LOCALAPPDATA%\Vivaldi\Application\vivaldi.exe")]),
            ("Waterfox", [r"C:\Program Files\Waterfox\waterfox.exe"]),
            ("Tor Browser", [os.path.expandvars(r"%USERPROFILE%\Desktop\Tor Browser\Browser\firefox.exe")]),
            ("LibreWolf", [r"C:\Program Files\LibreWolf\librewolf.exe"]),
            ("Chromium", [os.path.expandvars(r"%LOCALAPPDATA%\Chromium\Application\chrome.exe")]),
            ("Pale Moon", [r"C:\Program Files\Pale Moon\palemoon.exe"]),
            ("Maxthon", [r"C:\Program Files\Maxthon\Bin\Maxthon.exe"]),
            ("Slimjet", [r"C:\Program Files\Slimjet\slimjet.exe"]),
            ("Comodo Dragon", [r"C:\Program Files\Comodo\Dragon\dragon.exe"]),
            ("SeaMonkey", [r"C:\Program Files\SeaMonkey\seamonkey.exe"]),
            ("SRWare Iron", [r"C:\Program Files\SRWare Iron\iron.exe", r"C:\Program Files (x86)\SRWare Iron\iron.exe"]),
            ("Yandex Browser", [os.path.expandvars(r"%LOCALAPPDATA%\Yandex\YandexBrowser\Application\browser.exe")]),
            ("UC Browser", [os.path.expandvars(r"%LOCALAPPDATA%\UCBrowser\Application\UCBrowser.exe")]),
            ("Avast Secure Browser", [r"C:\Program Files\AVAST Software\Browser\Application\AvastBrowser.exe"]),
            ("AVG Secure Browser", [r"C:\Program Files\AVG\Browser\Application\AVGBrowser.exe"]),
            ("Torch", [os.path.expandvars(r"%LOCALAPPDATA%\Torch\Application\torch.exe")]),
            ("CoolNovo", [r"C:\Program Files\CoolNovo\coolnovo.exe"]),
            ("Naver Whale", [r"C:\Program Files\Naver\Naver Whale\Application\whale.exe"]),
            ("Iridium", [r"C:\Program Files\Iridium\iridium.exe"]),
            ("Epic Privacy Browser", [r"C:\Program Files\Epic Privacy Browser\Application\epic.exe", os.path.expandvars(r"%LOCALAPPDATA%\Epic Privacy Browser\Application\epic.exe")]),
            ("CentBrowser", [os.path.expandvars(r"%LOCALAPPDATA%\CentBrowser\Application\chrome.exe")]),
            ("360 Browser", [r"C:\Program Files\360\360Browser\360Chrome.exe"]),
            ("Coc Coc", [os.path.expandvars(r"%LOCALAPPDATA%\CocCoc\Browser\Application\browser.exe")]),
            ("Firefox Developer Edition", [r"C:\Program Files\Firefox Developer Edition\firefox.exe"]),
            ("Zen Browser", [r"C:\Program Files\Zen Browser\zen.exe"]),
            ("K-Meleon", [r"C:\Program Files\K-Meleon\k-meleon.exe"]),
            ("Basilisk", [r"C:\Program Files\Basilisk\basilisk.exe"]),
            ("IceCat", [r"C:\Program Files\GNU IceCat\icecat.exe"]),
            ("Internet Explorer", [r"C:\Program Files\Internet Explorer\iexplore.exe"]),
            ("Safari", [r"C:\Program Files\Safari\Safari.exe", r"C:\Program Files (x86)\Safari\Safari.exe"]),
            ("Avant Browser", [r"C:\Program Files\Avant Browser\avant.exe"]),
            ("Lunascape", [r"C:\Program Files\Lunascape\Lunascape.exe"]),
            ("Midori", [r"C:\Program Files\Midori\midori.exe"]),
        ]
        
        for name, paths in browser_exe_paths:
            if name in found_browsers:
                continue
            for exe_path in paths:
                if os.path.exists(exe_path):
                    try:
                        version = get_exe_version(exe_path)
                        if not version:
                            version = get_ps(f"(Get-Item '{exe_path}').VersionInfo.ProductVersion")
                        if version and version != "Not Detected":
                            meta = BROWSER_META.get(name, {"engine": "Unknown", "discontinued": False})
                            browsers.append({"name": name, "version": version, "engine": meta["engine"], "discontinued": meta["discontinued"]})
                            found_browsers.add(name)
                            break
                    except Exception:
                        meta = BROWSER_META.get(name, {"engine": "Unknown", "discontinued": False})
                        browsers.append({"name": name, "version": "Installed", "engine": meta["engine"], "discontinued": meta["discontinued"]})
                        found_browsers.add(name)
                        break
        
        results['browsers'] = browsers
        # Precompute status labels using backend dynamic versions
        status_map = {}
        latest_map = _get_latest_versions()
        for b in browsers:
            status_map[b['name']] = check_browser_version(b['name'], b.get('version', ''))
        results['browser_status'] = status_map
        results['latest_versions'] = latest_map

        # ---------------- STORAGE ----------------
        _progress("Analyzing storage...", 85)
        storage = []
        for part in psutil.disk_partitions():
            if 'fixed' in part.opts:
                try:
                    u = psutil.disk_usage(part.mountpoint)
                    storage.append({
                        "drive": part.device,
                        "total": f"{u.total // (1024**3)}GB",
                        "used": f"{u.used // (1024**3)}GB",
                        "percent": u.percent
                    })
                except:
                    continue
        results['storage'] = storage

        # Programs moved to dedicated function get_programs()

        # ---------------- HARDWARE INFO ----------------
        _progress("Gathering hardware information...", 90)
        results['cpu'] = get_ps("(Get-CimInstance Win32_Processor).Name")
        results['motherboard'] = get_ps("(Get-CimInstance Win32_BaseBoard).Product")
        mobo_manufacturer = get_ps("(Get-CimInstance Win32_BaseBoard).Manufacturer")
        if mobo_manufacturer and mobo_manufacturer != "Not Detected":
            results['motherboard'] = f"{mobo_manufacturer} {results['motherboard']}"
        
        # RAM info
        ram_total = get_ps("[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)")
        ram_speed = get_ps("(Get-CimInstance Win32_PhysicalMemory | Select-Object -First 1).Speed")
        results['ram'] = f"{ram_total} GB" + (f" @ {ram_speed} MHz" if ram_speed and ram_speed != "Not Detected" else "")

        # ---------------- PASSWORD MANAGERS ----------------
        _progress("Checking password managers...", 95)
        password_managers = []
        pm_detection = [
            ("1Password", [r"Software\AgileBits\1Password", r"SOFTWARE\AgileBits\1Password"], [r"C:\Program Files\1Password\app\1Password.exe", r"C:\Users\*\AppData\Local\1Password\app\*\1Password.exe"]),
            ("LastPass", [r"Software\LastPass", r"SOFTWARE\LastPass"], [r"C:\Program Files (x86)\LastPass\lastpass.exe"]),
            ("Dashlane", [r"Software\Dashlane\Dashlane"], [r"C:\Program Files\Dashlane\Dashlane.exe"]),
            ("Bitwarden", [r"Software\Bitwarden"], [r"C:\Program Files\Bitwarden\Bitwarden.exe", r"C:\Users\*\AppData\Local\Programs\Bitwarden\Bitwarden.exe"]),
            ("Keeper", [r"Software\Keeper Security"], [r"C:\Program Files (x86)\Keeper\keeper.exe"]),
            ("NordPass", [r"Software\NordPass"], [r"C:\Program Files\NordPass\NordPass.exe", r"C:\Users\*\AppData\Local\Programs\nordpass\NordPass.exe"]),
            ("RoboForm", [r"Software\Siber Systems\RoboForm"], [r"C:\Program Files (x86)\Siber Systems\AI RoboForm\RoboForm.exe"]),
            ("Enpass", [r"Software\Enpass"], [r"C:\Program Files\Enpass\Enpass.exe"]),
            ("Sticky Password", [r"Software\Sticky Password"], [r"C:\Program Files\Sticky Password\stpass.exe"]),
            ("KeePass", [], [r"C:\Program Files\KeePass Password Safe 2\KeePass.exe", r"C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe"]),
            ("Proton Pass", [r"Software\Proton\Proton Pass"], []),
            ("True Key", [r"Software\Intel Security\True Key", r"SOFTWARE\TrueKey"], [r"C:\Program Files\Intel Security\True Key\TrueKey.exe"]),
            ("Password Safe", [], [r"C:\Program Files\Password Safe\pwsafe.exe", r"C:\Program Files (x86)\Password Safe\pwsafe.exe"]),
            ("Zoho Vault", [r"Software\Zoho\Vault"], []),
            ("mSecure", [r"Software\mSeven Software\mSecure"], []),
            ("SafeInCloud", [r"Software\SafeInCloud"], []),
        ]
        
        for name, reg_paths, exe_paths in pm_detection:
            found = False
            # Check registry
            for reg_path in reg_paths:
                try:
                    hive = winreg.HKEY_CURRENT_USER if reg_path.startswith("Software") else winreg.HKEY_LOCAL_MACHINE
                    with winreg.OpenKey(hive, reg_path):
                        found = True
                        break
                except:
                    pass
            # Check exe paths
            if not found:
                for exe_path in exe_paths:
                    if '*' in exe_path:
                        if glob.glob(exe_path):
                            found = True
                            break
                    elif os.path.exists(exe_path):
                        found = True
                        break
            if found:
                password_managers.append(name)
                risk_count += 1
        
        results['password_managers'] = password_managers

        # ---------------- REMOTE SOFTWARE (RISK) ----------------
        _progress("Checking remote access software...", 98)
        remote_software = []
        rs_detection = [
            ("TeamViewer", [r"SOFTWARE\TeamViewer", r"Software\TeamViewer"], [r"C:\Program Files\TeamViewer\TeamViewer.exe", r"C:\Program Files (x86)\TeamViewer\TeamViewer.exe"]),
            ("AnyDesk", [r"SOFTWARE\AnyDesk", r"Software\AnyDesk"], [r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", r"C:\Users\*\AppData\Roaming\AnyDesk\AnyDesk.exe"]),
            ("LogMeIn", [r"SOFTWARE\LogMeIn"], [r"C:\Program Files (x86)\LogMeIn\x64\LogMeIn.exe"]),
            ("RustDesk", [], [r"C:\Program Files\RustDesk\rustdesk.exe", r"C:\Users\*\AppData\Roaming\RustDesk\rustdesk.exe"]),
            ("Splashtop", [r"SOFTWARE\Splashtop Inc."], [r"C:\Program Files (x86)\Splashtop\Splashtop Remote\Client\SRClient.exe"]),
            ("RemotePC", [r"SOFTWARE\RemotePC"], [r"C:\Program Files (x86)\RemotePC\RemotePC.exe"]),
            ("ConnectWise Control", [r"SOFTWARE\ScreenConnect Client"], [r"C:\Program Files (x86)\ScreenConnect Client*\ScreenConnect.ClientService.exe"]),
            ("GoToMyPC", [r"SOFTWARE\Citrix\GoToMyPC"], [r"C:\Program Files (x86)\Citrix\GoToMyPC\*\g2mcomm.exe"]),
            ("Chrome Remote Desktop", [], [r"C:\Program Files (x86)\Google\Chrome Remote Desktop\*\remoting_host.exe"]),
            ("VNC Server", [r"SOFTWARE\RealVNC"], [r"C:\Program Files\RealVNC\VNC Server\vncserver.exe"]),
            ("UltraVNC", [], [r"C:\Program Files\uvnc bvba\UltraVNC\winvnc.exe"]),
            ("Parsec", [], [r"C:\Program Files\Parsec\parsecd.exe", r"C:\Users\*\AppData\Roaming\Parsec\parsecd.exe"]),
            ("BeyondTrust", [r"SOFTWARE\Bomgar"], [r"C:\Program Files\Bomgar\bomgar-scc.exe"]),
            ("Dameware", [r"SOFTWARE\SolarWinds\DameWare Mini Remote Control"], [r"C:\Program Files\SolarWinds\DameWare Mini Remote Control\DWRCC.exe"]),
            ("Supremo", [], [r"C:\Program Files\Supremo\Supremo.exe"]),
            ("Remote Utilities", [r"SOFTWARE\Remote Utilities"], [r"C:\Program Files\Remote Utilities - Host\rutserv.exe"]),
            ("Radmin", [r"SOFTWARE\Radmin"], [r"C:\Program Files\Radmin\Radmin.exe"]),
            ("AeroAdmin", [], [r"C:\Program Files\AeroAdmin\AeroAdmin.exe"]),
            ("LiteManager", [], [r"C:\Program Files\LiteManager\ROMServer.exe"]),
            ("Zoho Assist", [r"SOFTWARE\ZohoMeetingManager"], []),
            ("ShowMyPC", [], [r"C:\Program Files\ShowMyPC\ShowMyPC.exe"]),
        ]
        
        for name, reg_paths, exe_paths in rs_detection:
            found = False
            for reg_path in reg_paths:
                try:
                    hive = winreg.HKEY_LOCAL_MACHINE if reg_path.startswith("SOFTWARE") else winreg.HKEY_CURRENT_USER
                    with winreg.OpenKey(hive, reg_path):
                        found = True
                        break
                except:
                    pass
            if not found:
                for exe_path in exe_paths:
                    if '*' in exe_path:
                        if glob.glob(exe_path):
                            found = True
                            break
                    elif os.path.exists(exe_path):
                        found = True
                        break
            if found:
                remote_software.append(name)
                risk_count += 1
        
        results['remote_software'] = remote_software

        # ---------------- IE DETECTION FOR WIN 10/11 ----------------
        ie_detected = False
        win_release = platform.release()  # '10', '11', etc.
        for b in browsers:
            if b.get('name') == 'Internet Explorer':
                ie_detected = True
                break
        results['ie_detected'] = ie_detected
        results['win_release'] = win_release

        # ---------------- ADDITIONAL SECURITY CHECKS ----------------
        additional_risks = []
        
        # Check Windows Update status
        update_status = get_ps("(Get-Service wuauserv).Status")
        results['windows_update'] = "Running" if "Running" in update_status else "Stopped"
        if "Running" not in update_status:
            caution_count += 1
        
        # Check Remote Desktop status
        rdp_enabled = get_ps("Get-ItemPropertyValue -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue")
        results['remote_desktop'] = "Disabled" if rdp_enabled == "1" else "Enabled"
        if rdp_enabled != "1":
            caution_count += 1
        
        # Check Guest account status
        guest_enabled = get_ps("(Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled")
        results['guest_account'] = "Disabled" if "False" in guest_enabled else "Enabled"
        if "True" in guest_enabled:
            risk_count += 1
        
        # Check Auto-login
        auto_login = get_ps("Get-ItemPropertyValue -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -ErrorAction SilentlyContinue")
        results['auto_login'] = "Enabled" if auto_login == "1" else "Disabled"
        if auto_login == "1":
            risk_count += 1
        
        # Check Windows Defender Real-time Protection & Version
        defender_realtime = get_ps("Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled")
        results['defender_realtime'] = "Enabled" if "True" in defender_realtime else "Disabled"
        if "True" not in defender_realtime:
            risk_count += 1
        
        # Get Windows Defender version
        defender_version = get_ps("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureVersion")
        results['defender_version'] = defender_version if defender_version and defender_version != "Not Detected" else "Unknown"

        results['risk_factor'] = risk_count
        results['caution_factor'] = caution_count
    
        _progress("Scan complete!", 100)
        return results

    except Exception as e:
        print("SCAN FAILED:", e)
        import traceback
        traceback.print_exc()
        return {
            "user": "Unknown",
            "risk_factor": 0,
            "caution_factor": 0,
            "storage": [],
            "browsers": [],
            "av_details": [],
            "fw_details": {"products": [], "windows_fw_enabled": False, "third_party_count": 0},
            "drive_encryption": "Unknown",
            "windows_version": "Unknown",
            "windows_build": "Unknown",
            "os_caption": "Unknown",
            "service_pack": "Unknown",
            "os_security": {"secure_boot": "Unknown", "tpm": "Unknown", "vbs": "Unknown"},
            "user_security": {"uac": "Unknown", "account_type": "Unknown", "is_admin": "Unknown"},
            "lock_security": {"password_set": "Unknown", "lock_screen": "Unknown", "sleep_timeout": "Unknown"},
            "windows_update": "Unknown",
            "remote_desktop": "Unknown",
            "guest_account": "Unknown",
            "auto_login": "Unknown",
            "defender_realtime": "Unknown",
            "defender_version": "Unknown",
            "total_program_size": "0 GB",
            "password_managers": [],
            "remote_software": [],
            "cpu": "Unknown",
            "motherboard": "Unknown",
            "ram": "Unknown"
        }

# Known Windows/System publishers for source classification
_SYSTEM_PUBLISHERS = [
    'microsoft', 'windows', 'intel', 'nvidia', 'amd', 'realtek', 'qualcomm',
    'broadcom', 'synaptics', 'conexant', 'dolby', 'maxx audio',
]

def _is_system_program(entry):
    """Determine if a program is a Windows/system component."""
    pub = (entry.get('Publisher') or '').lower()
    name = (entry.get('DisplayName') or '').lower()
    sys_comp = entry.get('SystemComponent')
    if sys_comp and str(sys_comp) == '1':
        return True
    for sp in _SYSTEM_PUBLISHERS:
        if sp in pub:
            return True
    # Common Windows component patterns
    if any(kw in name for kw in ['driver', 'runtime', '.net framework', 'visual c++', 'redistributable', 'windows sdk', 'windows kit']):
        return True
    return False


@eel.expose
def get_programs():
    """Return installed programs for Apps & Programs page, with bad software list and totals."""
    try:
        progs = []
        total_mb = 0.0
        system_mb = 0.0
        user_mb = 0.0
        store_mb = 0.0
        seen = set()
        for entry in enumerate_uninstall_entries():
            name = (entry.get('DisplayName') or '').strip()
            if not name or name in seen:
                continue
            seen.add(name)
            try:
                mb = round(float(entry.get('EstimatedSize', 0)) / 1024.0, 2)
            except Exception:
                mb = 0.0
            pub = entry.get('Publisher', '') or ''
            uninstall_str = entry.get('UninstallString', '') or ''
            is_sys = _is_system_program(entry)
            source = "Windows" if is_sys else "User"
            progs.append({"name": name, "size": mb, "publisher": pub, "source": source, "uninstall": uninstall_str})
            total_mb += mb
            if is_sys:
                system_mb += mb
            else:
                user_mb += mb
        # Microsoft Store apps
        try:
            store_apps_raw = get_ps("Get-AppxPackage | Where-Object {$_.IsFramework -eq $false -and $_.SignatureKind -eq 'Store'} | Select-Object Name, Publisher, InstallLocation | ConvertTo-Json")
            if store_apps_raw and store_apps_raw != "Not Detected":
                apps = json.loads(store_apps_raw)
                if isinstance(apps, dict):
                    apps = [apps]
                for app in apps:
                    app_name = app.get('Name', '')
                    if not app_name:
                        continue
                    display_name = app_name.split('.')[-1] if '.' in app_name else app_name
                    if display_name in seen:
                        continue
                    seen.add(display_name)
                    # Try to get store app size from install location
                    app_mb = 0.0
                    loc = app.get('InstallLocation', '')
                    if loc and os.path.isdir(loc):
                        try:
                            total_bytes = sum(os.path.getsize(os.path.join(dp, f)) for dp, dn, fnames in os.walk(loc) for f in fnames)
                            app_mb = round(total_bytes / (1024 * 1024), 2)
                        except Exception:
                            pass
                    progs.append({
                        "name": display_name,
                        "size": app_mb,
                        "publisher": app.get('Publisher', 'Microsoft Store'),
                        "source": "Store",
                        "uninstall": ""
                    })
                    store_mb += app_mb
                    total_mb += app_mb
        except Exception:
            pass
        progs.sort(key=lambda x: x['name'].lower())
        # Bad software detection
        BAD_SOFTWARE = [
            'McAfee', 'Norton', 'Avast', 'AVG', 'CCleaner', 'IObit', 'Advanced SystemCare', 'Driver Booster',
            'uTorrent', 'Clean Master', 'PC Optimizer Pro', 'MyCleanPC', 'WinZip', 'Ask Toolbar',
            'Conduit', 'Babylon', 'Toolbar'
        ]
        bad_hits = []
        for p in progs:
            for b in BAD_SOFTWARE:
                if b.lower() in p['name'].lower():
                    bad_hits.append(p['name'])
                    break
        return {
            "programs": progs,
            "total_program_size": f"{round(total_mb / 1024.0, 2)} GB",
            "program_count": len(progs),
            "bad_software": bad_hits,
            "size_breakdown": {
                "system_size": f"{round(system_mb / 1024.0, 2)} GB",
                "user_size": f"{round(user_mb / 1024.0, 2)} GB",
                "store_size": f"{round(store_mb / 1024.0, 2)} GB",
                "system_mb": round(system_mb, 2),
                "user_mb": round(user_mb, 2),
                "store_mb": round(store_mb, 2)
            }
        }
    except Exception as e:
        return {"programs": [], "total_program_size": "0 GB", "program_count": 0, "bad_software": [], "size_breakdown": {"system_size": "0 GB", "user_size": "0 GB", "store_size": "0 GB", "system_mb": 0, "user_mb": 0, "store_mb": 0}}


@eel.expose
def check_browser_version(browser_name, version):
    """Check if browser version is latest. Returns: 'good', 'risk', or 'caution'"""
    try:
        if not version or version in ["Detected", "Installed", "Not Detected"]:
            return "caution"
        major = int(str(version).split('.')[0])
        latest_map = _get_latest_versions()
        latest = latest_map.get(browser_name)
        if isinstance(latest, int):
            if major >= latest:
                return "good"
            if major >= latest - 2:
                return "caution"
            return "risk"
        return "caution"
    except Exception:
        return "caution"

# ==================== NETWORK SECURITY ====================

# Known malicious / suspicious DNS servers (subset of threat intel)
KNOWN_BAD_DNS = [
    "198.51.100.1", "203.0.113.1", "192.0.2.1",
    "185.228.168.10", "185.228.169.10",  # Examples from blocklists
    "208.67.220.123",  # Placeholder - should be updated from real threat intel
    "146.112.61.104", "146.112.61.105",  # Umbrella block page
    "199.85.126.20", "199.85.127.20",  # Norton ConnectSafe (discontinued)
    "77.88.8.7", "77.88.8.3",  # Yandex DNS (potential data collection)
    # Add more from threat intel feeds as needed
]

VPN_DETECTION = [
    ("NordVPN", [r"SOFTWARE\NordVPN"], [r"C:\Program Files\NordVPN\NordVPN.exe"]),
    ("ExpressVPN", [r"SOFTWARE\ExpressVPN"], [r"C:\Program Files (x86)\ExpressVPN\expressvpn-ui\ExpressVPN.exe"]),
    ("Surfshark", [r"SOFTWARE\Surfshark"], [r"C:\Program Files\Surfshark\Surfshark.exe"]),
    ("CyberGhost", [r"SOFTWARE\CyberGhost"], [r"C:\Program Files\CyberGhost 8\CyberGhost.exe"]),
    ("Private Internet Access", [r"SOFTWARE\Private Internet Access"], [r"C:\Program Files\Private Internet Access\pia-client.exe"]),
    ("ProtonVPN", [r"SOFTWARE\Proton\VPN"], [r"C:\Program Files\Proton\VPN\ProtonVPN.exe"]),
    ("Windscribe", [r"SOFTWARE\Windscribe"], [r"C:\Program Files\Windscribe\Windscribe.exe"]),
    ("Mullvad VPN", [r"SOFTWARE\Mullvad VPN"], [r"C:\Program Files\Mullvad VPN\mullvad-vpn.exe"]),
    ("TunnelBear", [r"SOFTWARE\TunnelBear"], [r"C:\Program Files (x86)\TunnelBear\TunnelBear.exe"]),
    ("Hotspot Shield", [r"SOFTWARE\Hotspot Shield", r"SOFTWARE\AnchorFree\Hotspot Shield"], [r"C:\Program Files\Hotspot Shield\bin\hsscp.exe"]),
    ("IPVanish", [r"SOFTWARE\IPVanish"], [r"C:\Program Files\IPVanish\IPVanish.exe"]),
    ("WireGuard", [r"SOFTWARE\WireGuard"], [r"C:\Program Files\WireGuard\wireguard.exe"]),
    ("OpenVPN", [r"SOFTWARE\OpenVPN"], [r"C:\Program Files\OpenVPN\bin\openvpn-gui.exe"]),
    ("Cisco AnyConnect", [r"SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client"], [r"C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"]),
    ("GlobalProtect", [r"SOFTWARE\Palo Alto Networks\GlobalProtect"], [r"C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe"]),
    ("FortiClient", [r"SOFTWARE\Fortinet\FortiClient"], [r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe"]),
    ("Pulse Secure", [r"SOFTWARE\Pulse Secure"], [r"C:\Program Files (x86)\Pulse Secure\Pulse\PulseSecure.exe"]),
    ("SoftEther VPN", [], [r"C:\Program Files\SoftEther VPN Client\vpnclient.exe"]),
    ("HideMyAss", [r"SOFTWARE\HMA! Pro VPN"], []),
    ("TorGuard", [], [r"C:\Program Files\TorGuard\TorGuard.exe"]),
    ("IVPN", [], [r"C:\Program Files\IVPN Client\IVPN.exe"]),
    ("AirVPN", [], [r"C:\Program Files\AirVPN\Eddie-UI.exe"]),
    ("StrongVPN", [r"SOFTWARE\StrongVPN"], []),
    ("VyprVPN", [r"SOFTWARE\Golden Frog\VyprVPN"], [r"C:\Program Files\VyprVPN\VyprVPN.exe"]),
    ("Kaspersky VPN", [r"SOFTWARE\KasperskyLab\KSDE"], [r"C:\Program Files (x86)\Kaspersky Lab\Kaspersky VPN Secure Connection*\ksde.exe"]),
]


@eel.expose
def get_network_info():
    """Gather network adapter info, DNS config, known-bad DNS checks, VPN detection,
    gateway, IPv6, APIPA detection, internet connectivity, and dumping software."""
    result = {"adapters": [], "dns_servers": [], "dns_alerts": [], "vpn_clients": [],
              "internet_connected": False, "dumping_software": []}
    try:
        # --- Internet connectivity check ---
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=4)
            result['internet_connected'] = True
        except Exception:
            result['internet_connected'] = False

        # --- Network adapters with DNS ---
        dns_raw = ps_first([
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses | ConvertTo-Json",
            "netsh interface ip show dns | Out-String"
        ])
        adapters = []
        all_dns = []
        try:
            dns_data = json.loads(dns_raw)
            if isinstance(dns_data, dict):
                dns_data = [dns_data]
            for entry in dns_data:
                alias = entry.get('InterfaceAlias', 'Unknown')
                servers = entry.get('ServerAddresses', [])
                if isinstance(servers, str):
                    servers = [servers]
                adapters.append({"name": alias, "dns": servers})
                all_dns.extend(servers)
        except (json.JSONDecodeError, TypeError):
            if dns_raw and dns_raw != "Not Detected":
                lines = dns_raw.split('\n')
                current_iface = ""
                current_dns = []
                for line in lines:
                    line = line.strip()
                    if 'Configuration for interface' in line:
                        if current_iface:
                            adapters.append({"name": current_iface, "dns": current_dns})
                            all_dns.extend(current_dns)
                        current_iface = line.split('"')[1] if '"' in line else line
                        current_dns = []
                    elif line and line[0].isdigit():
                        current_dns.append(line.split()[0])
                if current_iface:
                    adapters.append({"name": current_iface, "dns": current_dns})
                    all_dns.extend(current_dns)
        result['dns_servers'] = list(set(all_dns))

        # Check against known-bad DNS
        for ip in set(all_dns):
            if ip in KNOWN_BAD_DNS:
                result['dns_alerts'].append(f"Suspicious DNS server detected: {ip}")

        # --- IPv4 addresses ---
        ip_raw = ps_first([
            "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | Select-Object InterfaceAlias, IPAddress, PrefixLength | ConvertTo-Json",
            "ipconfig | Out-String"
        ])
        try:
            ip_data = json.loads(ip_raw)
            if isinstance(ip_data, dict):
                ip_data = [ip_data]
            for entry in ip_data:
                alias = entry.get('InterfaceAlias', '')
                for a in adapters:
                    if a['name'] == alias:
                        a['ip'] = entry.get('IPAddress', '')
                        a['prefix'] = entry.get('PrefixLength', '')
        except Exception:
            pass

        # --- IPv6 addresses ---
        try:
            ipv6_raw = get_ps("Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | Select-Object InterfaceAlias, IPAddress | ConvertTo-Json")
            if ipv6_raw and ipv6_raw != "Not Detected":
                ipv6_data = json.loads(ipv6_raw)
                if isinstance(ipv6_data, dict):
                    ipv6_data = [ipv6_data]
                for entry in ipv6_data:
                    alias = entry.get('InterfaceAlias', '')
                    for a in adapters:
                        if a['name'] == alias and 'ipv6' not in a:
                            a['ipv6'] = entry.get('IPAddress', '')
        except Exception:
            pass

        # --- Gateway per adapter ---
        try:
            gw_raw = get_ps("Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object InterfaceAlias, NextHop | ConvertTo-Json")
            if gw_raw and gw_raw != "Not Detected":
                gw_data = json.loads(gw_raw)
                if isinstance(gw_data, dict):
                    gw_data = [gw_data]
                for entry in gw_data:
                    alias = entry.get('InterfaceAlias', '')
                    for a in adapters:
                        if a['name'] == alias:
                            a['gateway'] = entry.get('NextHop', '')
        except Exception:
            pass

        # --- Adapter type classification ---
        try:
            adapter_details_raw = get_ps(
                "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MediaType | ConvertTo-Json"
            )
            if adapter_details_raw and adapter_details_raw != "Not Detected":
                ad_data = json.loads(adapter_details_raw)
                if isinstance(ad_data, dict):
                    ad_data = [ad_data]
                for ad in ad_data:
                    ad_name = ad.get('Name', '')
                    desc = (ad.get('InterfaceDescription') or '').lower()
                    status = ad.get('Status', '')
                    for a in adapters:
                        if a['name'] == ad_name:
                            a['status'] = status
                            # Classify type
                            if any(kw in desc for kw in ['wi-fi', 'wifi', 'wireless', '802.11', 'wlan']):
                                a['type'] = 'wifi'
                            elif any(kw in desc for kw in ['virtual', 'vmware', 'virtualbox', 'hyper-v', 'vethernet']):
                                a['type'] = 'virtual'
                            elif any(kw in desc for kw in ['loopback', 'localhost']):
                                a['type'] = 'loopback'
                            elif any(kw in a['name'].lower() for kw in ['loopback', 'localhost']):
                                a['type'] = 'loopback'
                            elif any(kw in a['name'].lower() for kw in ['vethernet', 'vmware', 'virtualbox', 'virtual']):
                                a['type'] = 'virtual'
                            else:
                                a['type'] = 'ethernet'
                            break
        except Exception:
            pass

        # Set defaults and detect APIPA
        for a in adapters:
            a.setdefault('ip', '')
            a.setdefault('prefix', '')
            a.setdefault('ipv6', 'None')
            a.setdefault('gateway', '')
            a.setdefault('type', 'ethernet')
            a.setdefault('status', '')
            # APIPA detection (169.254.x.x)
            ip_addr = a.get('ip', '')
            a['is_apipa'] = ip_addr.startswith('169.254.') if ip_addr else False

        # Sort: wifi/main first, then ethernet, then virtual/loopback
        type_order = {'wifi': 0, 'ethernet': 1, 'virtual': 2, 'loopback': 3}
        adapters.sort(key=lambda x: type_order.get(x.get('type', 'ethernet'), 1))
        result['adapters'] = adapters

        # --- VPN detection ---
        vpn_found = []
        for name, reg_paths, exe_paths in VPN_DETECTION:
            found = False
            for rp in reg_paths:
                try:
                    hive = winreg.HKEY_LOCAL_MACHINE
                    with winreg.OpenKey(hive, rp):
                        found = True
                        break
                except Exception:
                    pass
            if not found:
                for ep in exe_paths:
                    if '*' in ep:
                        if glob.glob(ep):
                            found = True
                            break
                    elif os.path.exists(ep):
                        found = True
                        break
            if found:
                vpn_found.append(name)
        result['vpn_clients'] = vpn_found

        # --- VPN active tunnel detection ---
        result['vpn_active'] = False
        result['vpn_protocol'] = ''
        result['vpn_adapter_name'] = ''
        try:
            # Check for active VPN/TAP/TUN adapters
            vpn_adapter_raw = get_ps(
                "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and ("
                "$_.InterfaceDescription -like '*TAP*' -or "
                "$_.InterfaceDescription -like '*TUN*' -or "
                "$_.InterfaceDescription -like '*VPN*' -or "
                "$_.InterfaceDescription -like '*WireGuard*' -or "
                "$_.InterfaceDescription -like '*Wintun*' -or "
                "$_.InterfaceDescription -like '*Windscribe*' -or "
                "$_.InterfaceDescription -like '*Nord*' -or "
                "$_.InterfaceDescription -like '*Proton*' -or "
                "$_.InterfaceDescription -like '*Surfshark*' -or "
                "$_.Name -like '*VPN*' -or "
                "$_.Name -like '*WireGuard*')} | "
                "Select-Object Name, InterfaceDescription, Status | ConvertTo-Json"
            )
            if vpn_adapter_raw and vpn_adapter_raw != "Not Detected":
                vpn_ad = json.loads(vpn_adapter_raw)
                if isinstance(vpn_ad, dict):
                    vpn_ad = [vpn_ad]
                if vpn_ad:
                    result['vpn_active'] = True
                    result['vpn_adapter_name'] = vpn_ad[0].get('Name', '')
                    desc = (vpn_ad[0].get('InterfaceDescription') or '').lower()
                    if 'wireguard' in desc or 'wintun' in desc:
                        result['vpn_protocol'] = 'WireGuard'
                    elif 'tap' in desc:
                        result['vpn_protocol'] = 'OpenVPN (TAP)'
                    elif 'tun' in desc:
                        result['vpn_protocol'] = 'OpenVPN (TUN)'
                    else:
                        result['vpn_protocol'] = 'Unknown'
            # Also check Windows built-in VPN (IKEv2/L2TP/PPTP/SSTP)
            if not result['vpn_active']:
                ras_raw = get_ps("Get-VpnConnection | Where-Object {$_.ConnectionStatus -eq 'Connected'} | Select-Object Name, TunnelType | ConvertTo-Json")
                if ras_raw and ras_raw != "Not Detected":
                    ras = json.loads(ras_raw)
                    if isinstance(ras, dict):
                        ras = [ras]
                    if ras:
                        result['vpn_active'] = True
                        result['vpn_adapter_name'] = ras[0].get('Name', '')
                        result['vpn_protocol'] = ras[0].get('TunnelType', 'Unknown')
        except Exception:
            pass

        # --- Interface dumping / packet capture software detection ---
        DUMPING_SOFTWARE = [
            ("Wireshark", [r"SOFTWARE\Wireshark", r"SOFTWARE\WOW6432Node\Wireshark"],
             [r"C:\Program Files\Wireshark\Wireshark.exe"]),
            ("Npcap", [r"SOFTWARE\Npcap"], [r"C:\Program Files\Npcap\NPFInstall.exe"]),
            ("WinPcap", [r"SOFTWARE\WinPcap"], []),
            ("Microsoft Network Monitor", [r"SOFTWARE\Microsoft\Netmon3"],
             [r"C:\Program Files\Microsoft Network Monitor 3\netmon.exe"]),
            ("RawCap", [], [r"C:\Program Files\RawCap\RawCap.exe"]),
            ("SmartSniff", [], [r"C:\Program Files\NirSoft\SmartSniff\smsniff.exe"]),
            ("Fiddler", [r"SOFTWARE\Telerik\Fiddler"],
             [r"C:\Program Files\Fiddler\Fiddler.exe", r"C:\Users\*\AppData\Local\Programs\Fiddler\Fiddler.exe"]),
            ("Charles Proxy", [], [r"C:\Program Files\Charles\Charles.exe"]),
        ]
        dump_found = []
        for dname, dreg, dexe in DUMPING_SOFTWARE:
            found = False
            for rp in dreg:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rp):
                        found = True
                        break
                except Exception:
                    pass
            if not found:
                for ep in dexe:
                    if '*' in ep:
                        if glob.glob(ep):
                            found = True
                            break
                    elif os.path.exists(ep):
                        found = True
                        break
            if found:
                dump_found.append(dname)
        result['dumping_software'] = dump_found

        # --- WiFi Security ---
        try:
            wifi_raw = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                timeout=10, stderr=subprocess.STDOUT, shell=True
            ).decode(errors='ignore').strip()
            wifi_info = {}
            for line in wifi_raw.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, _, val = line.partition(':')
                    wifi_info[key.strip().lower()] = val.strip()
            ssid = wifi_info.get('ssid', '')
            auth = wifi_info.get('authentication', '')
            cipher = wifi_info.get('cipher', '')
            signal = wifi_info.get('signal', '')
            radio = wifi_info.get('radio type', '')
            channel = wifi_info.get('channel', '')
            rx_rate = wifi_info.get('receive rate (mbps)', '')
            tx_rate = wifi_info.get('transmit rate (mbps)', '')
            if ssid:
                result['wifi_security'] = {
                    'status': 'Connected',
                    'ssid': ssid,
                    'authentication': auth,
                    'cipher': cipher,
                    'secured': auth.lower() not in ('open', ''),
                    'wps_enabled': None,
                    'signal': signal,
                    'radio_type': radio,
                    'channel': channel,
                    'rx_rate': rx_rate,
                    'tx_rate': tx_rate,
                }
            else:
                result['wifi_security'] = {'status': 'Not connected to WiFi'}
        except Exception:
            result['wifi_security'] = {'status': 'Not connected to WiFi'}

        # --- SSH / Telnet feature detection ---
        try:
            ssh_svc = get_ps("Get-Service sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status")
            result['ssh_server_enabled'] = bool(ssh_svc and ssh_svc not in ('Not Detected', ''))
        except Exception:
            result['ssh_server_enabled'] = False
        try:
            telnet_state = get_ps(
                "(Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue).State"
            )
            result['telnet_enabled'] = 'Enabled' in (telnet_state or '')
        except Exception:
            result['telnet_enabled'] = False

        # --- Public IP addresses ---
        result['public_ip'] = ''
        result['public_ipv6'] = ''
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
                result['public_ip'] = r.read().decode().strip()
        except Exception:
            pass
        try:
            with urllib.request.urlopen("https://api64.ipify.org", timeout=5) as r:
                v6 = r.read().decode().strip()
                if ':' in v6:  # Only store if actually IPv6
                    result['public_ipv6'] = v6
        except Exception:
            pass

        # --- Network profile per adapter (Public / Private / Domain) ---
        try:
            profile_raw = get_ps(
                "Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory | ConvertTo-Json"
            )
            if profile_raw and profile_raw != "Not Detected":
                profile_data = json.loads(profile_raw)
                if isinstance(profile_data, dict):
                    profile_data = [profile_data]
                for pf in profile_data:
                    alias = pf.get('InterfaceAlias', '')
                    cat = pf.get('NetworkCategory', '')
                    # Map numeric values: 0=Public, 1=Private, 2=DomainAuthenticated
                    if isinstance(cat, int):
                        cat = {0: 'Public', 1: 'Private', 2: 'Domain'}.get(cat, str(cat))
                    for a in adapters:
                        if a['name'] == alias:
                            a['network_profile'] = str(cat)
        except Exception:
            pass
        for a in adapters:
            a.setdefault('network_profile', '')

    except Exception as e:
        result['error'] = str(e)
    return result


# ==================== VIRUSTOTAL ====================

_VT_CONFIG_DIR = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'SystemShield')
_VT_CONFIG_FILE = os.path.join(_VT_CONFIG_DIR, 'config.json')


@eel.expose
def vt_save_api_key(key):
    try:
        os.makedirs(_VT_CONFIG_DIR, exist_ok=True)
        cfg = {}
        if os.path.exists(_VT_CONFIG_FILE):
            with open(_VT_CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
        cfg['vt_api_key'] = key
        with open(_VT_CONFIG_FILE, 'w') as f:
            json.dump(cfg, f)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def vt_get_api_key():
    try:
        if os.path.exists(_VT_CONFIG_FILE):
            with open(_VT_CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
            return cfg.get('vt_api_key', '')
    except Exception:
        pass
    return ''


@eel.expose
def vt_remove_api_key():
    """Remove saved VT API key."""
    try:
        if os.path.exists(_VT_CONFIG_FILE):
            with open(_VT_CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
            cfg.pop('vt_api_key', None)
            with open(_VT_CONFIG_FILE, 'w') as f:
                json.dump(cfg, f)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def vt_pick_and_scan_file():
    """Open a file picker dialog and scan the selected file on VirusTotal."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        filepath = filedialog.askopenfilename(title="Select file to scan on VirusTotal")
        root.destroy()
        if not filepath:
            return {"error": "No file selected"}
        return vt_scan_file(filepath)
    except Exception as e:
        return {"error": str(e)}


@eel.expose
def vt_scan_file(filepath):
    """Upload a file to VirusTotal for scanning. Returns scan results or ID."""
    try:
        api_key = vt_get_api_key()
        if not api_key:
            return {"error": "No API key configured"}
        if not os.path.exists(filepath):
            return {"error": "File not found"}
        # First check if hash is already known
        sha256 = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
        result = vt_check_hash(sha256)
        if result and not result.get('error'):
            return result
        # Upload file
        import http.client
        import mimetypes
        boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
        filename = os.path.basename(filepath)
        with open(filepath, 'rb') as f:
            file_data = f.read()
        body = (f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                f'Content-Type: {mimetypes.guess_type(filename)[0] or "application/octet-stream"}\r\n\r\n').encode()
        body += file_data + f'\r\n--{boundary}--\r\n'.encode()
        req = urllib.request.Request(
            'https://www.virustotal.com/api/v3/files',
            data=body,
            headers={
                'x-apikey': api_key,
                'Content-Type': f'multipart/form-data; boundary={boundary}'
            }
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
        analysis_id = data.get('data', {}).get('id', '')
        return {"status": "queued", "analysis_id": analysis_id, "sha256": sha256}
    except Exception as e:
        return {"error": str(e)}


@eel.expose
def vt_check_hash(hash_val):
    """Look up a file hash on VirusTotal."""
    try:
        api_key = vt_get_api_key()
        if not api_key:
            return {"error": "No API key configured"}
        req = urllib.request.Request(
            f'https://www.virustotal.com/api/v3/files/{hash_val}',
            headers={'x-apikey': api_key}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        results = attrs.get('last_analysis_results', {})
        engines = []
        for eng, info in results.items():
            if info.get('category') in ('malicious', 'suspicious'):
                engines.append({"engine": eng, "result": info.get('result', ''), "category": info.get('category', '')})
        return {
            "found": True,
            "sha256": hash_val,
            "stats": stats,
            "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "threat_label": attrs.get('popular_threat_classification', {}).get('suggested_threat_label', ''),
            "engines": engines[:50]  # Limit for UI
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False, "sha256": hash_val}
        return {"error": f"API error: {e.code}"}
    except Exception as e:
        return {"error": str(e)}


# ==================== SUMMARY / EXPORT ====================

@eel.expose
def generate_summary(scan_data, programs_data=None, network_data=None):
    """Build a structured summary report from scan data with multi-page support."""
    summary = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system": {
            "user": scan_data.get('user', 'Unknown'),
            "os": scan_data.get('os_caption', scan_data.get('os_name', 'Unknown')),
            "build": scan_data.get('windows_build', 'N/A'),
            "cpu": scan_data.get('cpu', 'Unknown'),
            "ram": scan_data.get('ram', 'Unknown'),
        },
        "risk_count": scan_data.get('risk_factor', 0),
        "caution_count": scan_data.get('caution_factor', 0),
        "issues": [],
    }
    # Collect issues with descriptions and remediation
    checks = [
        (scan_data.get('os_security', {}).get('secure_boot') != 'Enabled', 'Secure Boot is disabled or unsupported', 'Enable Secure Boot in BIOS/UEFI settings'),
        (scan_data.get('os_security', {}).get('tpm', '').find('Present') < 0, 'TPM not found', 'Check BIOS settings for TPM enablement'),
        (scan_data.get('os_security', {}).get('vbs') != 'Running', 'Core Isolation / VBS is off', 'Enable Memory Integrity in Windows Security'),
        (scan_data.get('drive_encryption') == 'Not Encrypted', 'Drive is not encrypted', 'Enable BitLocker Drive Encryption'),
        (scan_data.get('user_security', {}).get('is_admin') == 'Yes', 'Running as administrator', 'Use a standard user account for daily tasks'),
        (scan_data.get('user_security', {}).get('uac') != 'Enabled', 'UAC is disabled', 'Enable UAC in Control Panel \u2192 User Accounts'),
        (scan_data.get('lock_security', {}).get('password_set') == 'No', 'No password set', 'Set a password for your user account'),
        (scan_data.get('lock_security', {}).get('lock_screen') == 'Disabled', 'Lock screen timeout disabled', 'Enable screen lock in Settings \u2192 Personalization \u2192 Lock screen'),
        (scan_data.get('auto_login') == 'Enabled', 'Auto-login enabled', 'Disable automatic login'),
        (scan_data.get('guest_account') == 'Enabled', 'Guest account enabled', 'Disable the Guest account'),
        (scan_data.get('defender_realtime') == 'Disabled', 'Defender real-time protection off', 'Enable real-time protection in Windows Security'),
        (not scan_data.get('av_details'), 'No antivirus detected', 'Install antivirus software'),
        (not scan_data.get('fw_details', {}).get('windows_fw_enabled') and scan_data.get('fw_details', {}).get('third_party_count', 0) == 0,
         'No firewall active', 'Enable Windows Firewall or install a firewall'),
    ]
    for cond, desc, fix in checks:
        if cond:
            summary['issues'].append({"description": desc, "remediation": fix})
    for b in scan_data.get('browsers', []):
        if b.get('discontinued'):
            summary['issues'].append({"description": f"{b['name']} is discontinued", "remediation": "Uninstall and switch to a supported browser"})
    for pm in scan_data.get('password_managers', []):
        summary['issues'].append({"description": f"Password manager detected: {pm}", "remediation": "Evaluate if this is intentional; remove if unused"})
    for rs in scan_data.get('remote_software', []):
        summary['issues'].append({"description": f"Remote software detected: {rs}", "remediation": "Uninstall when not in active use"})

    # ---- Dashboard details for Page 2 ----
    summary['dashboard'] = {
        "os_security": scan_data.get('os_security', {}),
        "user_security": scan_data.get('user_security', {}),
        "lock_security": scan_data.get('lock_security', {}),
        "drive_encryption": scan_data.get('drive_encryption', 'Unknown'),
        "encryption_method": scan_data.get('encryption_method', 'Unknown'),
        "windows_update": scan_data.get('windows_update', 'Unknown'),
        "remote_desktop": scan_data.get('remote_desktop', 'Unknown'),
        "guest_account": scan_data.get('guest_account', 'Unknown'),
        "auto_login": scan_data.get('auto_login', 'Unknown'),
        "defender_realtime": scan_data.get('defender_realtime', 'Unknown'),
        "defender_version": scan_data.get('defender_version', 'Unknown'),
        "av_details": scan_data.get('av_details', []),
        "fw_details": scan_data.get('fw_details', {}),
        "browsers": scan_data.get('browsers', []),
        "password_managers": scan_data.get('password_managers', []),
        "remote_software": scan_data.get('remote_software', []),
        "storage": scan_data.get('storage', []),
    }

    # ---- Apps & Programs details for Page 3 ----
    if programs_data:
        summary['programs'] = {
            "program_count": programs_data.get('program_count', 0),
            "total_size": programs_data.get('total_program_size', '0 GB'),
            "size_breakdown": programs_data.get('size_breakdown', {}),
            "bad_software": programs_data.get('bad_software', []),
            "top_programs": [p['name'] + ' (' + (str(p['size']) + ' MB' if p.get('size') else '-') + ')'
                            for p in (programs_data.get('programs') or [])[:30]],
        }
    else:
        summary['programs'] = None

    # ---- Network Security details for Page 4 ----
    if network_data:
        summary['network'] = {
            "internet_connected": network_data.get('internet_connected', False),
            "vpn_clients": network_data.get('vpn_clients', []),
            "dns_servers": network_data.get('dns_servers', []),
            "dns_alerts": network_data.get('dns_alerts', []),
            "dumping_software": network_data.get('dumping_software', []),
            "wifi_security": network_data.get('wifi_security', {}),
            "ssh_server_enabled": network_data.get('ssh_server_enabled', False),
            "telnet_enabled": network_data.get('telnet_enabled', False),
            "public_ip": network_data.get('public_ip', ''),
            "public_ipv6": network_data.get('public_ipv6', ''),
            "adapters": [{
                "name": a.get('name', ''),
                "ip": a.get('ip', ''),
                "ipv6": a.get('ipv6', 'None'),
                "gateway": a.get('gateway', ''),
                "type": a.get('type', ''),
                "is_apipa": a.get('is_apipa', False),
            } for a in network_data.get('adapters', [])],
        }
    else:
        summary['network'] = None

    return summary


# ==================== SYSTEM OPERATIONS ====================

@eel.expose
def open_apps_settings():
    """Open Windows Apps & Features settings."""
    try:
        os.startfile("ms-settings:appsfeatures")
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def open_windows_features():
    """Open 'Turn Windows features on or off' dialog."""
    try:
        subprocess.Popen(["optionalfeatures"], shell=True)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def open_windows_update():
    """Open Windows Update settings."""
    try:
        os.startfile("ms-settings:windowsupdate")
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def uninstall_program(program_name):
    """Attempt to uninstall a program by name using its registry uninstall string."""
    try:
        for entry in enumerate_uninstall_entries():
            dname = (entry.get('DisplayName') or '').strip()
            if program_name.lower() in dname.lower():
                uninstall_str = (entry.get('UninstallString') or '').strip()
                if uninstall_str:
                    subprocess.Popen(uninstall_str, shell=True)
                    return {"status": "ok", "message": f"Uninstaller launched for {dname}"}
        return {"status": "error", "message": "Program not found or no uninstall string available"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def network_refresh():
    """Release and renew IP configuration on the default adapter."""
    try:
        subprocess.run(["ipconfig", "/release"], shell=True, timeout=15, capture_output=True)
        subprocess.run(["ipconfig", "/renew"], shell=True, timeout=30, capture_output=True)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def network_reset():
    """Reset the main network adapter (disable then re-enable)."""
    try:
        adapter = get_ps(
            "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Virtual*' "
            "-and $_.InterfaceDescription -notlike '*Loopback*'} | Select-Object -First 1).Name"
        )
        if adapter and adapter != "Not Detected":
            get_ps(f"Disable-NetAdapter -Name '{adapter}' -Confirm:$false")
            time.sleep(2)
            get_ps(f"Enable-NetAdapter -Name '{adapter}' -Confirm:$false")
            return {"status": "ok", "adapter": adapter}
        return {"status": "error", "message": "No suitable adapter found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def get_system_language():
    """Detect the system display language and installed language packs."""
    try:
        code = get_ps("(Get-Culture).Name")
        display = get_ps("(Get-Culture).DisplayName")
        installed = []
        try:
            raw = get_ps("Get-WinUserLanguageList | Select-Object LanguageTag | ConvertTo-Json")
            if raw and raw != "Not Detected":
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                installed = [d.get('LanguageTag', '') for d in data if d.get('LanguageTag')]
        except Exception:
            pass
        return {
            "code": code if code != "Not Detected" else "",
            "display": display if display != "Not Detected" else "",
            "installed": installed
        }
    except Exception:
        return {"code": "", "display": "", "installed": []}


@eel.expose
def open_browser_update(browser_name):
    """Launch a browser's own update / about page so it can self-update."""

    # Internal update-check URLs (opened inside the browser itself)
    internal_urls = {
        # Chromium-based
        "Google Chrome":        "chrome://settings/help",
        "Microsoft Edge":       "edge://settings/help",
        "Brave":                "brave://settings/help",
        "Opera":                "opera://update",
        "Opera GX":             "opera://update",
        "Vivaldi":              "vivaldi://about",
        "Yandex Browser":       "browser://settings/help",
        "Avast Secure Browser": "avast://settings/help",
        "AVG Secure Browser":   "avg://settings/help",
        "Naver Whale":          "whale://settings/help",
        "Chromium":             "chrome://settings/help",
        "CentBrowser":          "chrome://settings/help",
        "SRWare Iron":          "chrome://settings/help",
        "Slimjet":              "chrome://settings/help",
        "Comodo Dragon":        "chrome://settings/help",
        "Torch":                "chrome://settings/help",
        "CoolNovo":             "chrome://settings/help",
        "Iridium":              "chrome://settings/help",
        "Epic Privacy Browser": "chrome://settings/help",
        "360 Browser":          "chrome://settings/help",
        "Coc Coc":              "chrome://settings/help",
        # Gecko-based
        "Mozilla Firefox":           "about:preferences",
        "Firefox Developer Edition": "about:preferences",
        "Waterfox":                  "about:preferences",
        "LibreWolf":                 "about:preferences",
        "Zen Browser":               "about:preferences",
        "Tor Browser":               "about:preferences",
        "Pale Moon":                 "about:preferences",
        "SeaMonkey":                 "about:preferences",
        "K-Meleon":                  "about:preferences",
        "Basilisk":                  "about:preferences",
        "IceCat":                    "about:preferences",
    }

    # Known executable locations (mirrors the detection list)
    exe_map = {
        "Google Chrome":   [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"],
        "Microsoft Edge":  [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"],
        "Mozilla Firefox": [r"C:\Program Files\Mozilla Firefox\firefox.exe",
                            r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"],
        "Brave":           [r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"],
        "Opera":           [r"C:\Program Files\Opera\launcher.exe",
                            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera\launcher.exe")],
        "Opera GX":        [os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera GX\launcher.exe")],
        "Vivaldi":         [r"C:\Program Files\Vivaldi\Application\vivaldi.exe",
                            os.path.expandvars(r"%LOCALAPPDATA%\Vivaldi\Application\vivaldi.exe")],
        "Waterfox":        [r"C:\Program Files\Waterfox\waterfox.exe"],
        "LibreWolf":       [r"C:\Program Files\LibreWolf\librewolf.exe"],
        "Tor Browser":     [os.path.expandvars(r"%USERPROFILE%\Desktop\Tor Browser\Browser\firefox.exe")],
        "Chromium":        [os.path.expandvars(r"%LOCALAPPDATA%\Chromium\Application\chrome.exe")],
        "Pale Moon":       [r"C:\Program Files\Pale Moon\palemoon.exe"],
        "Slimjet":         [r"C:\Program Files\Slimjet\slimjet.exe"],
        "Comodo Dragon":   [r"C:\Program Files\Comodo\Dragon\dragon.exe"],
        "SeaMonkey":       [r"C:\Program Files\SeaMonkey\seamonkey.exe"],
        "SRWare Iron":     [r"C:\Program Files\SRWare Iron\iron.exe",
                            r"C:\Program Files (x86)\SRWare Iron\iron.exe"],
        "Yandex Browser":  [os.path.expandvars(r"%LOCALAPPDATA%\Yandex\YandexBrowser\Application\browser.exe")],
        "Avast Secure Browser": [r"C:\Program Files\AVAST Software\Browser\Application\AvastBrowser.exe"],
        "AVG Secure Browser":   [r"C:\Program Files\AVG\Browser\Application\AVGBrowser.exe"],
        "Torch":           [os.path.expandvars(r"%LOCALAPPDATA%\Torch\Application\torch.exe")],
        "Naver Whale":     [r"C:\Program Files\Naver\Naver Whale\Application\whale.exe"],
        "Iridium":         [r"C:\Program Files\Iridium\iridium.exe"],
        "Epic Privacy Browser": [r"C:\Program Files\Epic Privacy Browser\Application\epic.exe",
                                 os.path.expandvars(r"%LOCALAPPDATA%\Epic Privacy Browser\Application\epic.exe")],
        "CentBrowser":     [os.path.expandvars(r"%LOCALAPPDATA%\CentBrowser\Application\chrome.exe")],
        "360 Browser":     [r"C:\Program Files\360\360Browser\360Chrome.exe"],
        "Coc Coc":         [os.path.expandvars(r"%LOCALAPPDATA%\CocCoc\Browser\Application\browser.exe")],
        "Firefox Developer Edition": [r"C:\Program Files\Firefox Developer Edition\firefox.exe"],
        "Zen Browser":     [r"C:\Program Files\Zen Browser\zen.exe"],
        "Maxthon":         [r"C:\Program Files\Maxthon\Bin\Maxthon.exe"],
        "K-Meleon":        [r"C:\Program Files\K-Meleon\k-meleon.exe"],
        "Basilisk":        [r"C:\Program Files\Basilisk\basilisk.exe"],
        "IceCat":          [r"C:\Program Files\GNU IceCat\icecat.exe"],
        "CoolNovo":        [r"C:\Program Files\CoolNovo\coolnovo.exe"],
    }

    # Locate the executable on disk
    exe = None
    for p in exe_map.get(browser_name, []):
        if os.path.exists(p):
            exe = p
            break

    # Launch the browser with its internal update page
    internal_url = internal_urls.get(browser_name)
    if exe and internal_url:
        try:
            subprocess.Popen([exe, internal_url])
            return {"status": "ok", "message": f"Opening {browser_name} settings"}
        except Exception:
            pass

    # Fallback: open a web-based download / support page
    fallback_urls = {
        "Google Chrome":  "https://support.google.com/chrome/answer/95414",
        "Mozilla Firefox": "https://support.mozilla.org/en-US/kb/update-firefox-latest-release",
        "Opera":           "https://www.opera.com/download",
        "Opera GX":        "https://www.opera.com/gx",
        "Vivaldi":         "https://vivaldi.com/download/",
        "Maxthon":         "https://www.maxthon.com/",
    }
    url = fallback_urls.get(browser_name)
    if url:
        try:
            os.startfile(url)
            return {"status": "ok", "message": f"Opening download page for {browser_name}"}
        except Exception:
            pass

    return {"status": "error", "message": f"Could not open update page for {browser_name}"}


eel.start(
    'index.html',
    mode='edge',
    size=(1150, 950),
    port=0,
    cmdline_args=[
        '--new-window',
    ]
)
