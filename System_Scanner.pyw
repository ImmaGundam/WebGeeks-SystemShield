import eel
import platform
import psutil
import wmi
import winreg
import os
import subprocess
import urllib.request
import json
import glob

eel.init('web')

VERSION = "1.0"

def get_ps(cmd):
    try:
        return subprocess.check_output(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            timeout=15, stderr=subprocess.STDOUT, shell=True
        ).decode().strip()
    except:
        return "Not Detected"

@eel.expose
def check_for_updates():
    api_url = "https://api.github.com/repos/ImmaGundam/SystemShield/releases/latest"
    try:
        with urllib.request.urlopen(api_url) as response:
            data = json.loads(response.read().decode())
            latest_version = data['tag_name'].replace('v', '')
            if float(latest_version) > float(VERSION):
                return {"status": "update_available", "version": latest_version}
            return {"status": "up_to_date", "version": VERSION}
    except:
        return {"status": "error", "version": VERSION}

@eel.expose
def perform_scan():
    try:
        results = {}
        risk_count = 0
        caution_count = 0

        # ---------------- BASIC OS ----------------
        results['user'] = os.getlogin()
        results['os_name'] = f"{platform.system()} {platform.release()}"

        # Get detailed Windows info
        results['windows_version'] = get_ps("(Get-CimInstance Win32_OperatingSystem).Version")
        results['windows_build'] = get_ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber")
        results['os_caption'] = get_ps("(Get-CimInstance Win32_OperatingSystem).Caption")
        results['service_pack'] = get_ps("(Get-ComputerInfo).OsHardwareAbstractionLayer")

        # ---------------- SECURITY BASELINE ----------------
        sb_status = get_ps("Confirm-SecureBootUEFI")
        tpm_status = get_ps("(Get-Tpm).TpmPresent")
        vbs_status = get_ps("(Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard).VirtualizationBasedSecurityStatus")

        results['os_security'] = {
            "secure_boot": "Enabled" if "True" in sb_status else "Disabled/Unsupported",
            "tpm": "Present (v2.0)" if "True" in tpm_status else "Not Found",
            "vbs": "Running" if vbs_status == "2" else "Off"
        }

        if "True" not in sb_status: risk_count += 1
        if "True" not in tpm_status: risk_count += 1
        if vbs_status != "2": risk_count += 1

        # ---------------- DRIVE ENCRYPTION ----------------
        try:
            bitlocker_status = get_ps("Get-BitLockerVolume | Select-Object -ExpandProperty ProtectionStatus")
            results['drive_encryption'] = "Encrypted" if "1" in bitlocker_status else "Not Encrypted"
            if "1" not in bitlocker_status:
                risk_count += 1
        except:
            results['drive_encryption'] = "Unknown"

        # ---------------- PASSWORD & LOCK SCREEN ----------------
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
        is_admin = "True" in get_ps("([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')")
        uac_enabled = get_ps("Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA")
        
        # Check account type (Microsoft vs Local)
        account_type_check = get_ps("(Get-CimInstance Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).AccountType")
        ms_account = get_ps("Get-ItemPropertyValue -Path 'HKCU:\\Software\\Microsoft\\IdentityStore\\Cache\\*\\IdentityCache\\*' -Name UserName -ErrorAction SilentlyContinue 2>$null | Select-Object -First 1")
        
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
        av_raw = get_ps("Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName")
        av_list = [line.strip() for line in av_raw.split("\n") if line.strip() and line.strip().lower() not in ['displayname', '----------', '-----------', '------------', 'not detected', '']]
        
        # Check Windows Defender status separately
        defender_status = get_ps("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled")
        if "True" in defender_status and "Windows Defender" not in str(av_list):
            av_list.append("Windows Defender")
        
        if not av_list:
            risk_count += 1
        results['av_details'] = av_list

        # ---------------- FIREWALL ----------------
        fw_products = []
        
        # Check Windows Firewall profiles
        fw_domain = get_ps("(Get-NetFirewallProfile -Name Domain).Enabled")
        fw_private = get_ps("(Get-NetFirewallProfile -Name Private).Enabled")
        fw_public = get_ps("(Get-NetFirewallProfile -Name Public).Enabled")
        
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
        browsers = []
        found_browsers = set()
        
        # Registry paths for browser detection
        browser_registry = [
            ("Google Chrome", r"Software\Google\Chrome\BLBeacon", "version", winreg.HKEY_CURRENT_USER),
            ("Google Chrome", r"SOFTWARE\Google\Chrome\BLBeacon", "version", winreg.HKEY_LOCAL_MACHINE),
            ("Microsoft Edge", r"Software\Microsoft\Edge\BLBeacon", "version", winreg.HKEY_CURRENT_USER),
            ("Microsoft Edge", r"SOFTWARE\Microsoft\Edge\BLBeacon", "version", winreg.HKEY_LOCAL_MACHINE),
            ("Mozilla Firefox", r"SOFTWARE\Mozilla\Mozilla Firefox", "CurrentVersion", winreg.HKEY_LOCAL_MACHINE),
            ("Brave", r"Software\BraveSoftware\Brave-Browser\BLBeacon", "version", winreg.HKEY_CURRENT_USER),
            ("Brave", r"SOFTWARE\BraveSoftware\Brave-Browser\BLBeacon", "version", winreg.HKEY_LOCAL_MACHINE),
            ("Opera", r"Software\Opera Software", "Last Stable Install Path", winreg.HKEY_CURRENT_USER),
            ("Opera GX", r"Software\Opera Software\Opera GX Stable", "Last Stable Install Path", winreg.HKEY_CURRENT_USER),
            ("Vivaldi", r"Software\Vivaldi", "Version", winreg.HKEY_CURRENT_USER),
            ("Arc", r"Software\Arc\Arc", "Version", winreg.HKEY_CURRENT_USER),
        ]
        
        for name, path, value_name, hive in browser_registry:
            if name in found_browsers:
                continue
            try:
                with winreg.OpenKey(hive, path) as key:
                    v, _ = winreg.QueryValueEx(key, value_name)
                    if v:
                        browsers.append({"name": name, "version": str(v)})
                        found_browsers.add(name)
            except:
                continue
        
        # Check common browser executables for versions we might have missed
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
        ]
        
        for name, paths in browser_exe_paths:
            if name in found_browsers:
                continue
            for exe_path in paths:
                if os.path.exists(exe_path):
                    try:
                        version = get_ps(f"(Get-Item '{exe_path}').VersionInfo.ProductVersion")
                        if version and version != "Not Detected":
                            browsers.append({"name": name, "version": version})
                            found_browsers.add(name)
                            break
                    except:
                        browsers.append({"name": name, "version": "Installed"})
                        found_browsers.add(name)
                        break
        
        results['browsers'] = browsers

        # ---------------- STORAGE ----------------
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

        # ---------------- PROGRAMS ----------------
        progs = []
        total_mb = 0
        seen_programs = set()
        
        # Registry paths to scan for installed programs
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        
        for hive, path in registry_paths:
            try:
                with winreg.OpenKey(hive, path) as key:
                    subkey_count = winreg.QueryInfoKey(key)[0]
                    for i in range(subkey_count):
                        try:
                            s_key = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, s_key) as sub:
                                try:
                                    name = winreg.QueryValueEx(sub, "DisplayName")[0]
                                except:
                                    continue
                                
                                if not name or name in seen_programs:
                                    continue
                                seen_programs.add(name)
                                
                                try:
                                    size_kb = winreg.QueryValueEx(sub, "EstimatedSize")[0]
                                    mb = round(size_kb / 1024, 2)
                                except:
                                    mb = 0
                                
                                try:
                                    publisher = winreg.QueryValueEx(sub, "Publisher")[0]
                                except:
                                    publisher = ""
                                
                                progs.append({
                                    "name": name,
                                    "size": mb,
                                    "publisher": publisher,
                                    "source": "Desktop"
                                })
                                total_mb += mb
                        except:
                            continue
            except:
                continue
        
        # Get Microsoft Store apps
        try:
            store_apps_raw = get_ps("Get-AppxPackage | Where-Object {$_.IsFramework -eq $false -and $_.SignatureKind -eq 'Store'} | Select-Object Name, Publisher | ConvertTo-Json")
            if store_apps_raw and store_apps_raw != "Not Detected":
                store_apps = json.loads(store_apps_raw)
                if isinstance(store_apps, dict):
                    store_apps = [store_apps]
                for app in store_apps:
                    app_name = app.get('Name', '')
                    if app_name and app_name not in seen_programs:
                        # Clean up the name (remove package prefixes)
                        display_name = app_name.split('.')[-1] if '.' in app_name else app_name
                        seen_programs.add(app_name)
                        progs.append({
                            "name": display_name,
                            "size": 0,
                            "publisher": app.get('Publisher', 'Microsoft Store'),
                            "source": "Store"
                        })
        except:
            pass
        
        # Sort by name by default
        progs.sort(key=lambda x: x['name'].lower())
        
        results['programs'] = progs
        results['total_program_size'] = f"{round(total_mb / 1024, 2)} GB"
        results['program_count'] = len(progs)

        # ---------------- HARDWARE INFO ----------------
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

        return results

    except Exception as e:
        print("SCAN FAILED:", e)
        import traceback
        traceback.print_exc()
        return {
            "user": "Unknown",
            "risk_factor": 0,
            "caution_factor": 0,
            "programs": [],
            "program_count": 0,
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

# Known latest browser versions (updated periodically)
LATEST_BROWSER_VERSIONS = {
    "Google Chrome": 133,
    "Microsoft Edge": 133,
    "Mozilla Firefox": 135,
    "Brave": 133,
    "Opera": 116,
    "Opera GX": 116,
    "Vivaldi": 7,
    "Arc": 1,
}

@eel.expose
def check_browser_version(browser_name, version):
    """Check if browser version is latest. Returns: 'good', 'risk', or 'caution'"""
    try:
        if not version or version in ["Detected", "Installed", "Not Detected"]:
            return "caution"
        
        # Extract major version number
        major = int(str(version).split('.')[0])
        
        if browser_name in LATEST_BROWSER_VERSIONS:
            latest = LATEST_BROWSER_VERSIONS[browser_name]
            if major >= latest:
                return "good"
            elif major >= latest - 2:
                return "caution"  # Within 2 versions
            else:
                return "risk"
        return "caution"  # Unknown browser
    except:
        return "caution"

eel.start(
    'index.html',
    mode='chrome',
    size=(1150, 950),
    cmdline_args=[
        '--new-window',
    ]
)