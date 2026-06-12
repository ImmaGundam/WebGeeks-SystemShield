# scan_system.py - system scan module
# Purpose: Orchestrate full system scans and assemble dashboard result data.

import json
import os
import platform
import traceback

import psutil
import winreg

from core.browser_scan import (
    check_browser_version as check_browser_version_logic,
    detect_installed_browsers,
    get_latest_versions,
)
from core.detection_data import PM_DETECTION, RMM_DETECTION, RS_DETECTION
from core.scan_helpers import collect_hardware_profile, detect_secure_boot, detect_tpm
from core.system_utils import (
    _clean_detected,
    _gb_from_bytes,
    _get_nvidia_smi_details,
    _gpu_vendor,
    _match_registry_or_paths,
    get_ps,
    ps_first,
    read_registry_value,
)


def _emit_progress(progress_cb, msg, pct):
    """Send scan progress updates if callback is provided."""
    try:
        if progress_cb:
            progress_cb(msg, pct)
    except Exception:
        pass


def _default_scan_error_payload():
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
        "rmm_software": [],
        "cpu": "Unknown",
        "cpus": [],
        "gpus": [],
        "motherboard": "Unknown",
        "ram": "Unknown",
        "hardware_profile": {
            "system_manufacturer": "Undetected",
            "system_model": "Undetected",
            "device_type": "Undetected",
            "storage_devices": [],
            "memory_module_count": "Undetected",
            "memory_manufacturers": "Undetected",
            "uptime": "Undetected",
            "uptime_seconds": 0,
            "uptime_status": "good",
            "processors": [],
            "power_profile_name": "Undetected",
            "power_profile_guid": "Undetected",
        },
        "system_manufacturer": "Undetected",
        "system_model": "Undetected",
        "device_type": "Undetected",
        "storage_devices": [],
        "memory_module_count": "Undetected",
        "memory_manufacturers": "Undetected",
        "uptime": "Undetected",
        "uptime_seconds": 0,
        "uptime_status": "good",
        "processors": [],
        "power_profile_name": "Undetected",
        "power_profile_guid": "Undetected",
        "windows_recovery": "Unknown",
    }


def perform_scan_data(progress_cb):
    """Run the full SystemShield scan and return dashboard payload."""
    try:
        _emit_progress(progress_cb, "Starting system scan...", 0)

        results = {}
        results["detection_evidence"] = {
            "password_managers": {},
            "remote_software": {},
            "rmm_software": {},
        }
        risk_count = 0
        caution_count = 0

        _emit_progress(progress_cb, "Checking browser versions...", 5)
        _ = get_latest_versions()

        _emit_progress(progress_cb, "Collecting OS information...", 10)
        results["user"] = os.getlogin()
        results["os_name"] = f"{platform.system()} {platform.release()}"
        results["windows_version"] = get_ps("(Get-CimInstance Win32_OperatingSystem).Version")
        results["windows_build"] = get_ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber")
        results["os_caption"] = get_ps("(Get-CimInstance Win32_OperatingSystem).Caption")
        results["service_pack"] = get_ps("(Get-ComputerInfo).OsHardwareAbstractionLayer")

        _emit_progress(progress_cb, "Checking security baseline...", 20)
        sb_state = detect_secure_boot()
        tpm_version = detect_tpm()
        if tpm_version == "2.0":
            tpm_result = "Present (v2.0)"
        elif tpm_version == "1.2":
            tpm_result = "Present (v1.2)"
        elif tpm_version == "Present":
            tpm_result = "Present"
        else:
            tpm_result = "Not Found"

        vbs_status = ps_first(
            [
                "try { (Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard).VirtualizationBasedSecurityStatus.ToString() } catch { '0' }"
            ]
        )

        results["os_security"] = {
            "secure_boot": "Enabled" if sb_state == "Enabled" else "Disabled/Unsupported",
            "tpm": tpm_result,
            "vbs": "Running" if vbs_status.strip() == "2" else "Off",
        }
        if sb_state != "Enabled":
            risk_count += 1
        if tpm_version == "":
            risk_count += 1
        if vbs_status.strip() != "2":
            risk_count += 1

        _emit_progress(progress_cb, "Checking drive encryption...", 30)
        try:
            bitlocker_status = ps_first(
                [
                    "Get-BitLockerVolume | Select-Object -ExpandProperty ProtectionStatus",
                    "(manage-bde -status C:) | Select-String 'Percentage Encrypted' | ForEach-Object { ($_ -split ':')[1].Trim() }",
                ]
            )
            enc = False
            if bitlocker_status and bitlocker_status != "Not Detected":
                if any(x in bitlocker_status for x in ["1", "100%", "Encrypted"]):
                    enc = True
            results["drive_encryption"] = "Encrypted" if enc else "Not Encrypted"
            enc_method = "Unknown"
            enc_version = ""
            if enc:
                try:
                    enc_method_raw = ps_first(
                        [
                            r"manage-bde -status C: 2>$null | Select-String 'Encryption Method' | ForEach-Object { ($_ -split ':\s*',2)[1].Trim() }",
                            "try{(Get-BitLockerVolume -MountPoint C: -ErrorAction Stop).EncryptionMethod}catch{}",
                        ]
                    )
                    if (
                        enc_method_raw
                        and enc_method_raw != "Not Detected"
                        and len(enc_method_raw) < 80
                        and "Exception" not in enc_method_raw
                        and "Access denied" not in enc_method_raw
                    ):
                        enc_method = enc_method_raw
                    enc_ver_raw = ps_first(
                        [
                            r"manage-bde -status C: 2>$null | Select-String 'Version' | Select-Object -First 1 | ForEach-Object { ($_ -split ':\s*',2)[1].Trim() }",
                        ]
                    )
                    if (
                        enc_ver_raw
                        and enc_ver_raw != "Not Detected"
                        and len(enc_ver_raw) < 80
                        and "Exception" not in enc_ver_raw
                    ):
                        enc_version = enc_ver_raw
                except Exception:
                    pass
            if enc and enc_method == "Unknown":
                try:
                    os_sku = get_ps("(Get-CimInstance Win32_OperatingSystem).OperatingSystemSKU")
                    home_skus = ["4", "5", "98", "100", "101"]
                    if os_sku in home_skus:
                        enc_method = "Device Encryption"
                        enc_version = "XTS-AES 128-bit"
                    else:
                        enc_method = "BitLocker"
                except Exception:
                    pass
            if enc and enc_method in ("Unknown", "BitLocker"):
                try:
                    policy_method = get_ps(
                        "Get-ItemPropertyValue -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE' "
                        "-Name 'EncryptionMethodWithXtsOs' -ErrorAction SilentlyContinue"
                    )
                    method_map = {
                        "3": "AES-CBC 128-bit",
                        "4": "AES-CBC 256-bit",
                        "6": "XTS-AES 128-bit",
                        "7": "XTS-AES 256-bit",
                    }
                    if policy_method in method_map:
                        enc_version = method_map[policy_method]
                except Exception:
                    pass
            results["encryption_method"] = enc_method
            results["encryption_version"] = enc_version
            if not enc:
                risk_count += 1
        except Exception:
            results["drive_encryption"] = "Unknown"
            results["encryption_method"] = "Unknown"
            results["encryption_version"] = ""

        _emit_progress(progress_cb, "Checking password security...", 40)
        pwd_last_set = get_ps("(Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue).PasswordLastSet")
        net_user_output = get_ps(
            "net user $env:USERNAME | Select-String 'Password required' | ForEach-Object { $_.Line }"
        )
        limit_blank = get_ps(
            "Get-ItemPropertyValue -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue"
        )

        password_set = False
        if pwd_last_set and pwd_last_set != "Not Detected" and pwd_last_set.strip() != "":
            password_set = True
        elif "Yes" in net_user_output:
            password_set = True
        elif limit_blank == "1":
            password_set = True

        timeout_none = {"0x00000000", "0", "", "Not Detected"}
        screensaver_locked = False
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop") as desktop_key:
                def _query_value(key, name):
                    try:
                        return winreg.QueryValueEx(key, name)[0]
                    except Exception:
                        return None

                ss_active = _query_value(desktop_key, "ScreenSaveActive")
                ss_secure = _query_value(desktop_key, "ScreenSaverIsSecure")
                ss_timeout = _query_value(desktop_key, "ScreenSaveTimeOut")
            if str(ss_active) == "1" and str(ss_secure) == "1":
                try:
                    screensaver_locked = int(ss_timeout) > 0
                except Exception:
                    screensaver_locked = True
        except Exception:
            pass

        display_timeout_raw = get_ps(
            "powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE | "
            "Select-String 'Current AC Power Setting Index' | "
            "ForEach-Object { ($_ -split ':')[1].Trim() }"
        ).strip()
        sleep_timeout_raw = get_ps(
            "powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | "
            "Select-String 'Current AC Power Setting Index' | "
            "ForEach-Object { ($_ -split ':')[1].Trim() }"
        ).strip()
        display_timeout_set = display_timeout_raw not in timeout_none
        sleep_enabled = sleep_timeout_raw not in timeout_none
        lock_enabled = screensaver_locked or display_timeout_set or sleep_enabled

        results["lock_security"] = {
            "password_set": "Yes" if password_set else "No",
            "lock_screen": "Enabled" if lock_enabled else "Disabled",
            "sleep_timeout": "Enabled" if sleep_enabled else "Disabled",
        }

        if not password_set:
            risk_count += 1
        if not lock_enabled:
            caution_count += 1
        if not sleep_enabled:
            caution_count += 1

        _emit_progress(progress_cb, "Checking user security settings...", 50)
        is_admin = "True" in get_ps(
            "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')"
        )
        uac_enabled = ps_first(
            [
                "(Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA).EnableLUA",
                "Write-Output 1",
            ]
        )
        ms_account = ps_first(
            [
                "Get-ItemPropertyValue -Path 'HKCU:\\Software\\Microsoft\\IdentityStore\\Cache\\*\\IdentityCache\\*' -Name UserName -ErrorAction SilentlyContinue 2>$null | Select-Object -First 1",
                "Write-Output ''",
            ]
        )
        domain_joined = get_ps("(Get-CimInstance Win32_ComputerSystem).PartOfDomain")
        if "@" in ms_account:
            account_type = "Microsoft Account"
        elif "True" in domain_joined:
            account_type = "Domain Account"
        else:
            account_type = "Local Account"

        results["user_security"] = {
            "is_admin": "Yes" if is_admin else "No",
            "uac": "Enabled" if "1" in uac_enabled else "Disabled",
            "account_type": account_type,
        }
        if is_admin:
            risk_count += 1
        if "1" not in uac_enabled:
            risk_count += 1

        _emit_progress(progress_cb, "Checking antivirus status...", 60)
        av_raw = get_ps(
            "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName"
        )
        av_list = [
            line.strip()
            for line in av_raw.split("\n")
            if line.strip()
            and line.strip().lower()
            not in ["displayname", "----------", "-----------", "------------", "not detected", ""]
        ]

        defender_status = get_ps("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled")
        if "True" in defender_status and "Windows Defender" not in str(av_list):
            av_list.append("Windows Defender")

        mb_in_av = any("malwarebytes" in av.lower() for av in av_list)
        if not mb_in_av:
            mb_installed = False
            mb_reg_paths = [r"SOFTWARE\Malwarebytes", r"SOFTWARE\Malwarebytes' Anti-Malware"]
            mb_exe_paths = [
                r"C:\Program Files\Malwarebytes\Anti-Malware\mbam.exe",
                r"C:\Program Files (x86)\Malwarebytes\Anti-Malware\mbam.exe",
            ]
            for reg_path in mb_reg_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path):
                        mb_installed = True
                        break
                except Exception:
                    pass
            if not mb_installed:
                for exe_path in mb_exe_paths:
                    if os.path.exists(exe_path):
                        mb_installed = True
                        break
            if mb_installed:
                av_list.append("Malwarebytes (Free)")

        if not av_list:
            risk_count += 1
        results["av_details"] = av_list

        _emit_progress(progress_cb, "Checking firewall configuration...", 70)
        fw_products = []
        fw_domain = ps_first(
            [
                "(Get-NetFirewallProfile -Name Domain).Enabled",
                "(netsh advfirewall show domainprofile | Select-String 'State') -match 'ON'",
            ]
        )
        fw_private = ps_first(
            [
                "(Get-NetFirewallProfile -Name Private).Enabled",
                "(netsh advfirewall show privateprofile | Select-String 'State') -match 'ON'",
            ]
        )
        fw_public = ps_first(
            [
                "(Get-NetFirewallProfile -Name Public).Enabled",
                "(netsh advfirewall show publicprofile | Select-String 'State') -match 'ON'",
            ]
        )
        windows_fw_enabled = "True" in fw_domain or "True" in fw_private or "True" in fw_public
        if windows_fw_enabled:
            profiles_on = []
            if "True" in fw_domain:
                profiles_on.append("Domain")
            if "True" in fw_private:
                profiles_on.append("Private")
            if "True" in fw_public:
                profiles_on.append("Public")
            fw_products.append({"name": "Windows Firewall", "profiles": profiles_on, "status": "Enabled"})

        fw_raw = get_ps(
            "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName FirewallProduct | Select-Object -ExpandProperty displayName"
        )
        third_party = [
            line.strip()
            for line in fw_raw.split("\n")
            if line.strip()
            and line.strip().lower()
            not in [
                "displayname",
                "----------",
                "-----------",
                "------------",
                "not detected",
                "windows firewall",
                "",
            ]
        ]
        for fw in third_party:
            fw_products.append({"name": fw, "profiles": [], "status": "Active"})

        results["fw_details"] = {
            "products": fw_products,
            "windows_fw_enabled": windows_fw_enabled,
            "third_party_count": len(third_party),
        }
        if not windows_fw_enabled and len(third_party) == 0:
            risk_count += 1

        _emit_progress(progress_cb, "Detecting browsers and versions...", 75)
        browsers = detect_installed_browsers()
        results["browsers"] = browsers
        status_map = {}
        latest_map = get_latest_versions()
        for browser in browsers:
            status_map[browser["name"]] = check_browser_version_logic(
                browser["name"], browser.get("version", "")
            )
        results["browser_status"] = status_map
        results["latest_versions"] = latest_map

        _emit_progress(progress_cb, "Analyzing storage...", 85)
        storage = []
        for part in psutil.disk_partitions():
            if "fixed" in part.opts:
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    storage.append(
                        {
                            "drive": part.device,
                            "total": f"{usage.total // (1024**3)}GB",
                            "used": f"{usage.used // (1024**3)}GB",
                            "percent": usage.percent,
                        }
                    )
                except Exception:
                    continue
        results["storage"] = storage

        _emit_progress(progress_cb, "Gathering hardware information...", 90)
        cpu_raw = get_ps("Get-CimInstance Win32_Processor | Select-Object Name, DeviceID | ConvertTo-Json")
        try:
            cpu_json = json.loads(cpu_raw)
            if isinstance(cpu_json, dict):
                cpu_json = [cpu_json]
            cpu_json.sort(key=lambda item: str(item.get("DeviceID", "CPU9")))
            results["cpus"] = [item.get("Name", "Unknown").strip() for item in cpu_json if item.get("Name")]
            results["cpu"] = results["cpus"][0] if results["cpus"] else "Unknown"
        except Exception:
            fallback_cpu = get_ps("(Get-CimInstance Win32_Processor | Select-Object -First 1).Name")
            results["cpus"] = [fallback_cpu] if fallback_cpu and fallback_cpu != "Not Detected" else ["Unknown"]
            results["cpu"] = results["cpus"][0]

        results["motherboard"] = get_ps("(Get-CimInstance Win32_BaseBoard).Product")
        mobo_manufacturer = get_ps("(Get-CimInstance Win32_BaseBoard).Manufacturer")
        if mobo_manufacturer and mobo_manufacturer != "Not Detected":
            results["motherboard"] = f"{mobo_manufacturer} {results['motherboard']}"

        ram_total = get_ps("[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)")
        ram_speed = get_ps("(Get-CimInstance Win32_PhysicalMemory | Select-Object -First 1).Speed")
        results["ram"] = f"{ram_total} GB" + (
            f" @ {ram_speed} MHz" if ram_speed and ram_speed != "Not Detected" else ""
        )

        gpu_raw = get_ps(
            "Get-CimInstance Win32_VideoController | "
            "Select-Object Name,CurrentHorizontalResolution,CurrentVerticalResolution,AdapterRAM,DriverVersion,DriverDate,CurrentRefreshRate,VideoProcessor | ConvertTo-Json"
        )
        try:
            gpu_json = json.loads(gpu_raw)
            if isinstance(gpu_json, dict):
                gpu_json = [gpu_json]

            def gpu_priority(gpu):
                name = (gpu.get("Name") or "").lower()
                if any(k in name for k in ["microsoft", "basic render", "remote desktop", "virtual", "hyper-v"]):
                    return 3
                if "intel" in name:
                    return 2
                return 1

            gpu_json.sort(key=gpu_priority)
            nvidia_details = _get_nvidia_smi_details()
            results["gpus"] = []
            for idx, gpu in enumerate(gpu_json):
                gpu_name = (gpu.get("Name") or "").strip()
                if not gpu_name:
                    continue
                width = gpu.get("CurrentHorizontalResolution")
                height = gpu.get("CurrentVerticalResolution")
                vendor = _gpu_vendor(gpu_name)
                adapter_ram = _gb_from_bytes(gpu.get("AdapterRAM"))
                driver_version = _clean_detected(gpu.get("DriverVersion"))
                gpu_clock = "Undetected"
                memory_clock = "Undetected"
                telemetry_source = "Windows WMI"
                if vendor == "NVIDIA" and nvidia_details:
                    match = None
                    for detail in nvidia_details:
                        detail_name = detail.get("name", "")
                        if detail_name and (
                            detail_name.lower() in gpu_name.lower() or gpu_name.lower() in detail_name.lower()
                        ):
                            match = detail
                            break
                    if match is None and idx < len(nvidia_details):
                        match = nvidia_details[idx]
                    if match:
                        adapter_ram = match.get("adapter_ram") or adapter_ram
                        driver_version = match.get("driver_version") or driver_version
                        gpu_clock = match.get("gpu_clock") or gpu_clock
                        memory_clock = match.get("memory_clock") or memory_clock
                        telemetry_source = match.get("telemetry_source") or telemetry_source
                refresh = _clean_detected(gpu.get("CurrentRefreshRate"))
                results["gpus"].append(
                    {
                        "name": gpu_name,
                        "vendor": vendor,
                        "resolution": f"{width}x{height}" if width and height else "",
                        "memory": adapter_ram,
                        "driver_version": driver_version,
                        "gpu_clock": gpu_clock,
                        "memory_clock": memory_clock,
                        "refresh_rate": f"{refresh} Hz" if refresh != "Undetected" else "Undetected",
                        "video_processor": _clean_detected(gpu.get("VideoProcessor")),
                        "telemetry_source": telemetry_source,
                    }
                )
        except Exception:
            results["gpus"] = []

        hardware_profile = collect_hardware_profile()
        results["hardware_profile"] = hardware_profile
        results["system_manufacturer"] = hardware_profile.get("system_manufacturer", "Undetected")
        results["system_model"] = hardware_profile.get("system_model", "Undetected")
        results["device_type"] = hardware_profile.get("device_type", "Undetected")
        results["storage_devices"] = hardware_profile.get("storage_devices", [])
        results["memory_module_count"] = hardware_profile.get("memory_module_count", "Undetected")
        results["memory_manufacturers"] = hardware_profile.get("memory_manufacturers", "Undetected")
        results["uptime"] = hardware_profile.get("uptime", "Undetected")
        results["uptime_seconds"] = hardware_profile.get("uptime_seconds", 0)
        results["uptime_status"] = hardware_profile.get("uptime_status", "good")
        results["processors"] = hardware_profile.get("processors", [])
        results["power_profile_name"] = hardware_profile.get("power_profile_name", "Undetected")
        results["power_profile_guid"] = hardware_profile.get("power_profile_guid", "Undetected")

        if results["uptime_status"] == "risk":
            risk_count += 1
        elif results["uptime_status"] == "caution":
            caution_count += 1

        _emit_progress(progress_cb, "Checking password managers...", 95)
        password_managers = []
        for name, reg_paths, exe_paths in PM_DETECTION:
            found, evidence = _match_registry_or_paths(reg_paths, exe_paths)
            if found:
                password_managers.append(name)
                results["detection_evidence"]["password_managers"][name] = evidence
        results["password_managers"] = password_managers

        _emit_progress(progress_cb, "Checking remote access software...", 98)
        remote_software = []
        for name, reg_paths, exe_paths in RS_DETECTION:
            found, evidence = _match_registry_or_paths(reg_paths, exe_paths)
            if found:
                remote_software.append(name)
                results["detection_evidence"]["remote_software"][name] = evidence
                risk_count += 1
        results["remote_software"] = remote_software

        _emit_progress(progress_cb, "Checking RMM platforms...", 99)
        rmm_software = []
        for name, reg_paths, exe_paths in RMM_DETECTION:
            found, evidence = _match_registry_or_paths(reg_paths, exe_paths)
            if found:
                rmm_software.append(name)
                results["detection_evidence"]["rmm_software"][name] = evidence
                caution_count += 1
        results["rmm_software"] = rmm_software

        ie_detected = False
        win_release = platform.release()
        for browser in browsers:
            if browser.get("name") == "Internet Explorer":
                ie_detected = True
                break
        results["ie_detected"] = ie_detected
        results["win_release"] = win_release

        update_status = get_ps("(Get-Service wuauserv).Status")
        results["windows_update"] = "Running" if "Running" in update_status else "Stopped"
        if "Running" not in update_status:
            caution_count += 1

        rdp_enabled = get_ps(
            "Get-ItemPropertyValue -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue"
        )
        results["remote_desktop"] = "Disabled" if rdp_enabled == "1" else "Enabled"
        if rdp_enabled != "1":
            caution_count += 1

        guest_enabled = get_ps("(Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled")
        results["guest_account"] = "Disabled" if "False" in guest_enabled else "Enabled"
        if "True" in guest_enabled:
            risk_count += 1

        auto_login = get_ps(
            "Get-ItemPropertyValue -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -ErrorAction SilentlyContinue"
        )
        results["auto_login"] = "Enabled" if auto_login == "1" else "Disabled"
        if auto_login == "1":
            risk_count += 1

        winre_result = "Unknown"
        winre_raw = get_ps(
            "try { $o = reagentc /info 2>&1 | Out-String; if ($o -match 'Windows RE status[^:]*:\\s*(\\S+)') { $Matches[1] } elseif ($o -match 'Enabled') { 'Enabled' } elseif ($o -match 'Disabled') { 'Disabled' } else { '' } } catch { '' }"
        )
        if winre_raw and winre_raw.strip() not in ("", "Not Detected"):
            status = winre_raw.strip().lower()
            if "enabled" in status:
                winre_result = "Enabled"
            elif "disabled" in status:
                winre_result = "Disabled"

        if winre_result == "Unknown":
            bcd_raw = get_ps(
                "try { $b = bcdedit /enum all 2>&1 | Out-String; if ($b -match 'Windows Recovery Environment') { 'Found' } else { '' } } catch { '' }"
            )
            if bcd_raw and "Found" in bcd_raw:
                winre_result = "Enabled"

        if winre_result == "Unknown":
            wr_val = read_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\WinREAgent",
                "Disabled",
            )
            if wr_val is None:
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SYSTEM\CurrentControlSet\Control\WinREAgent",
                    ):
                        winre_result = "Enabled"
                except Exception:
                    pass
            elif int(wr_val) == 1:
                winre_result = "Disabled"
            else:
                winre_result = "Enabled"

        if winre_result == "Unknown":
            part_raw = get_ps(
                "try { Get-Partition | Where-Object { $_.Type -eq 'Recovery' } | Measure-Object | Select-Object -ExpandProperty Count } catch { '0' }"
            )
            if part_raw and part_raw.strip() not in ("", "0", "Not Detected"):
                winre_result = "Enabled"

        if winre_result == "Unknown":
            for wim_path in [
                r"C:\Windows\System32\Recovery\Winre.wim",
                r"C:\Recovery\WindowsRE\Winre.wim",
            ]:
                if os.path.exists(wim_path):
                    winre_result = "Enabled"
                    break
        results["windows_recovery"] = winre_result

        defender_realtime = get_ps("Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled")
        results["defender_realtime"] = "Enabled" if "True" in defender_realtime else "Disabled"
        if "True" not in defender_realtime:
            risk_count += 1

        defender_version = get_ps("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureVersion")
        results["defender_version"] = (
            defender_version if defender_version and defender_version != "Not Detected" else "Unknown"
        )

        _emit_progress(progress_cb, "Finalizing scan results...", 95)
        results["risk_factor"] = risk_count
        results["caution_factor"] = caution_count

        _emit_progress(progress_cb, "Scan complete!", 100)
        return results
    except Exception as exc:
        print("SCAN FAILED:", exc)
        traceback.print_exc()
        return _default_scan_error_payload()
