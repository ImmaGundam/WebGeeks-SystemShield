import eel
import threading
import platform
import psutil
import wmi
import winreg
import sys
import os
import subprocess
import urllib.request
import urllib.error
import json
import glob
import hashlib
import time
from datetime import datetime
import re as _re
import socket

from detection_lists import (
    # Browser data
    LATEST_BROWSER_VERSIONS,
    BROWSER_META,
    BROWSER_REGISTRY,
    BROWSER_EXE_PATHS,
    # Name-based threat detection
    BAD_SOFTWARE,
    SCAMWARE,
    TORRENT_CLIENTS,
    CRYPTO_MINERS,
    HACKING_UTILS,
    DATA_EXFIL_TOOLS,
    REMOTE_SHELL_TOOLS,
    RAT_TOOLS,
    CREDENTIAL_STEALERS,
    # Registry + exe-path detection
    VPN_DETECTION,
    PM_DETECTION,
    RS_DETECTION,
    RMM_DETECTION,
    # Network / classification
    KNOWN_BAD_DNS,
    DUMPING_SOFTWARE,
    SYSTEM_PUBLISHERS,
)

# Optional dependency: pywin32 for EXE version info
try:
    import win32api  # type: ignore
    PYWIN32_AVAILABLE = True
except Exception:
    PYWIN32_AVAILABLE = False

def resource_path(relative_path):
    """Resolve a path relative to the script/exe location, regardless of CWD."""
    try:

        base = sys._MEIPASS
    except AttributeError:

        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)

html_file = resource_path("web/index.html")

eel.init(resource_path('web'))

# SystemShield application version. Keep this matched with About page and detection list comments.
VERSION = "1.3.2"

# Version 1.3.2 packaging note:
# icon.ico should live in web/data/icon.ico or data/icon.ico depending on repo layout.
# PyInstaller uses the same icon for the EXE/taskbar via --icon, while the HTML
# favicon provides the in-window/title icon used by the web UI.
APP_USER_MODEL_ID = "WebGeeks.SystemShield.1.3.2"


def _set_windows_app_user_model_id():
    """Set a stable Windows AppUserModelID for taskbar grouping/icon behavior.

    This is non-critical. The real EXE/taskbar icon still comes from the
    PyInstaller --icon option when compiled.
    """
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except Exception:
        pass


_set_windows_app_user_model_id()

def _progress(msg, pct):
    """Send scan progress update to the UI (non-critical)."""
    try:
        eel.update_scan_progress(msg, pct)
    except Exception:
        pass

# Fallback static versions loaded from detection_lists.py

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


def _match_registry_or_paths(reg_paths, exe_paths):
    """Return passive detection evidence for configured registry keys and exe paths.

    This does not modify the system. It only records which configured value
    caused a detection so the UI can show an analytical remediation profile.
    """
    evidence = []

    for reg_path in reg_paths:
        try:
            hive = winreg.HKEY_LOCAL_MACHINE if reg_path.startswith("SOFTWARE") else winreg.HKEY_CURRENT_USER
            with winreg.OpenKey(hive, reg_path):
                hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                evidence.append({"type": "registry", "value": f"{hive_name}\\{reg_path}"})
        except Exception:
            pass

    for exe_path in exe_paths:
        try:
            if '*' in exe_path:
                matches = glob.glob(exe_path)
                for match in matches[:5]:
                    evidence.append({"type": "path", "value": match})
            elif os.path.exists(exe_path):
                evidence.append({"type": "path", "value": exe_path})
        except Exception:
            pass

    return bool(evidence), evidence


def _clean_detected(value, default="Undetected"):
    """Normalize WMI/CIM values for display without exposing sensitive identifiers."""
    try:
        if value is None:
            return default
        s = str(value).strip()
        if not s:
            return default
        # Remove generic WMI filler text that does not identify the actual hardware.
        s = _re.sub(r"\((?:Standard disk drives|Fixed hard disk media)\)", "", s, flags=_re.I)
        s = _re.sub(r"\b(?:Standard disk drives|Fixed hard disk media)\b", "", s, flags=_re.I)
        s = _re.sub(r"\s{2,}", " ", s).strip(" -|,/\t")
        if not s or s.lower() in (
            "not detected", "none", "null", "unknown", "to be filled by o.e.m.",
            "system product name", "standard disk drives", "fixed hard disk media"
        ):
            return default
        return s
    except Exception:
        return default


def _json_as_list(raw):
    """Parse ConvertTo-Json output into a list."""
    try:
        if not raw or raw == "Not Detected":
            return []
        data = json.loads(raw)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def _gb_from_bytes(value):
    try:
        n = float(value)
        if n <= 0:
            return "Undetected"
        return f"{round(n / (1024 ** 3))} GB"
    except Exception:
        return "Undetected"


def _mb_from_kb(value):
    try:
        n = float(value)
        if n <= 0:
            return "Undetected"
        return f"{round(n / 1024)} MB"
    except Exception:
        return "Undetected"


def _mhz(value):
    try:
        n = int(float(value))
        if n <= 0:
            return "Undetected"
        return f"{n} MHz"
    except Exception:
        return "Undetected"


def _format_cache_kb(value):
    try:
        n = int(float(value))
        if n <= 0:
            return "Undetected"
        if n >= 1024:
            return f"{round(n / 1024)} MB"
        return f"{n} KB"
    except Exception:
        return "Undetected"


def _gpu_vendor(name):
    n = (name or "").lower()
    if "nvidia" in n or "geforce" in n or "quadro" in n or "rtx" in n or "gtx" in n:
        return "NVIDIA"
    if "amd" in n or "radeon" in n or "ati" in n:
        return "AMD"
    if "intel" in n or "iris" in n or "uhd" in n:
        return "Intel"
    if any(v in n for v in ("microsoft", "basic render", "remote desktop", "virtual", "hyper-v")):
        return "Virtual/Software"
    return "Undetected"


def _get_nvidia_smi_details():
    """Return NVIDIA GPU telemetry when nvidia-smi is available. No admin required."""
    candidates = [
        "nvidia-smi",
        r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
    ]
    query = [
        "--query-gpu=name,driver_version,memory.total,clocks.current.graphics,clocks.current.memory",
        "--format=csv,noheader,nounits",
    ]
    for exe in candidates:
        try:
            out = subprocess.check_output([exe] + query, timeout=5, stderr=subprocess.STDOUT).decode(errors="ignore").strip()
            if not out:
                continue
            rows = []
            for line in out.splitlines():
                parts = [p.strip() for p in line.split(",")]
                while len(parts) < 5:
                    parts.append("Undetected")
                rows.append({
                    "name": _clean_detected(parts[0]),
                    "driver_version": _clean_detected(parts[1]),
                    "adapter_ram": f"{parts[2]} MB" if parts[2] and parts[2].lower() != "[not supported]" else "Undetected",
                    "gpu_clock": f"{parts[3]} MHz" if parts[3] and parts[3].lower() != "[not supported]" else "Undetected",
                    "memory_clock": f"{parts[4]} MHz" if parts[4] and parts[4].lower() != "[not supported]" else "Undetected",
                    "telemetry_source": "nvidia-smi",
                })
            return rows
        except Exception:
            continue
    return []


def _format_uptime(seconds):
    try:
        total = max(0, int(seconds))
        days, rem = divmod(total, 86400)
        hours, rem = divmod(rem, 3600)
        minutes = rem // 60
        if days > 0:
            return f"{days} day{'s' if days != 1 else ''}, {hours} hour{'s' if hours != 1 else ''}"
        if hours > 0:
            return f"{hours} hour{'s' if hours != 1 else ''}, {minutes} min"
        return f"{minutes} min"
    except Exception:
        return "Undetected"


def _device_type_from_chassis(chassis_types, manufacturer="", model=""):
    text = f"{manufacturer} {model}".lower()
    if any(v in text for v in ("vmware", "virtualbox", "hyper-v", "qemu", "kvm", "parallels", "virtual")):
        return "Virtual Machine"
    try:
        vals = chassis_types
        if not isinstance(vals, (list, tuple)):
            vals = [vals]
        nums = set()
        for v in vals:
            try:
                nums.add(int(v))
            except Exception:
                pass
        laptop_codes = {8, 9, 10, 11, 12, 14, 30, 31, 32}
        desktop_codes = {3, 4, 5, 6, 7, 15, 16, 35, 36}
        if nums & laptop_codes:
            return "Laptop"
        if nums & desktop_codes:
            return "Desktop"
    except Exception:
        pass
    return "Undetected"


def _collect_hardware_profile():
    """Collect non-admin hardware inventory values for the Dashboard Hardware Profile."""
    profile = {
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
    }

    cs = _json_as_list(get_ps(
        "Get-CimInstance Win32_ComputerSystem | "
        "Select-Object Manufacturer,Model | ConvertTo-Json"
    ))
    if cs:
        profile["system_manufacturer"] = _clean_detected(cs[0].get("Manufacturer"))
        profile["system_model"] = _clean_detected(cs[0].get("Model"))

    enc = _json_as_list(get_ps(
        "Get-CimInstance Win32_SystemEnclosure | "
        "Select-Object ChassisTypes | ConvertTo-Json"
    ))
    chassis = enc[0].get("ChassisTypes") if enc else []
    profile["device_type"] = _device_type_from_chassis(
        chassis,
        profile["system_manufacturer"],
        profile["system_model"],
    )

    processors = _json_as_list(get_ps(
        "Get-CimInstance Win32_Processor | "
        "Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,CurrentClockSpeed,L2CacheSize,L3CacheSize,SocketDesignation | ConvertTo-Json"
    ))
    for cpu in processors:
        name = _clean_detected(cpu.get("Name"))
        manufacturer = _clean_detected(cpu.get("Manufacturer"))
        cores = _clean_detected(cpu.get("NumberOfCores"))
        threads = _clean_detected(cpu.get("NumberOfLogicalProcessors"))
        max_clock = _mhz(cpu.get("MaxClockSpeed"))
        current_clock = _mhz(cpu.get("CurrentClockSpeed"))
        l2 = _format_cache_kb(cpu.get("L2CacheSize"))
        l3 = _format_cache_kb(cpu.get("L3CacheSize"))
        socket = _clean_detected(cpu.get("SocketDesignation"))
        if name == manufacturer == cores == threads == max_clock == current_clock == l2 == l3 == socket == "Undetected":
            continue
        profile["processors"].append({
            "name": name,
            "manufacturer": manufacturer,
            "cores": cores,
            "threads": threads,
            "max_clock": max_clock,
            "current_clock": current_clock,
            "l2_cache": l2,
            "l3_cache": l3,
            "socket": socket,
        })

    power_raw = get_ps("powercfg /getactivescheme")
    if power_raw and power_raw != "Not Detected":
        try:
            m = _re.search(r"Power Scheme GUID:\s*([a-fA-F0-9\-]+)\s*(?:\((.*?)\))?", power_raw)
            if m:
                profile["power_profile_guid"] = m.group(1) or "Undetected"
                profile["power_profile_name"] = _clean_detected(m.group(2))
            else:
                profile["power_profile_name"] = _clean_detected(power_raw)
        except Exception:
            profile["power_profile_name"] = _clean_detected(power_raw)

    mem = _json_as_list(get_ps(
        "Get-CimInstance Win32_PhysicalMemory | "
        "Select-Object Manufacturer,Capacity,Speed | ConvertTo-Json"
    ))
    if mem:
        profile["memory_module_count"] = str(len(mem))
        manufacturers = []
        for m in mem:
            mf = _clean_detected(m.get("Manufacturer"))
            if mf != "Undetected" and mf not in manufacturers:
                manufacturers.append(mf)
        profile["memory_manufacturers"] = ", ".join(manufacturers) if manufacturers else "Undetected"

    disks = _json_as_list(get_ps(
        "Get-CimInstance Win32_DiskDrive | "
        "Select-Object Model,Manufacturer,MediaType,InterfaceType,Size | ConvertTo-Json"
    ))
    for d in disks:
        model = _clean_detected(d.get("Model"))
        manufacturer = _clean_detected(d.get("Manufacturer"))
        media_type = _clean_detected(d.get("MediaType"))
        interface_type = _clean_detected(d.get("InterfaceType"))
        size = _gb_from_bytes(d.get("Size"))
        if model == manufacturer == media_type == interface_type == size == "Undetected":
            continue
        profile["storage_devices"].append({
            "model": model,
            "manufacturer": manufacturer,
            "media_type": media_type,
            "interface": interface_type,
            "size": size,
        })

    try:
        uptime_seconds = int(time.time() - psutil.boot_time())
        profile["uptime_seconds"] = uptime_seconds
        profile["uptime"] = _format_uptime(uptime_seconds)
        days = uptime_seconds / 86400
        if days >= 14:
            profile["uptime_status"] = "risk"
        elif days >= 7:
            profile["uptime_status"] = "caution"
        else:
            profile["uptime_status"] = "good"
    except Exception:
        pass

    return profile


# ---- TPM ACPI hardware IDs (per Microsoft / vendor ACPI TPM spec) ----
_TPM2_ACPI_IDS = frozenset({
    "MSFT0101",  # Microsoft generic TPM 2.0
    "IFX0102",   # Infineon TPM 2.0
    "INTC0101",  # Intel PTT / fTPM 2.0
    "NTZ0101",   # Nuvoton TPM 2.0
    "CSCO0101",  # Cisco TPM 2.0
    "ATML0201",  # Atmel TPM 2.0
    "STM0201",   # STMicroelectronics TPM 2.0
})
_TPM1_ACPI_IDS = frozenset({
    "IFX0101",   # Infineon TPM 1.2
    "BCM0101",   # Broadcom TPM 1.2
    "ATM1200",   # Atmel TPM 1.2
    "STM0101",   # STMicroelectronics TPM 1.2
    "SNO2601",   # Sinosun TPM 1.2
    "WEC0101",   # Winbond TPM 1.2
    "ROCC0000",  # Rockchip TPM 1.2
})


def _detect_secure_boot():
    """Detect Secure Boot state via registry without admin privileges.
    Reads HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State.
    Returns 'Enabled', 'Disabled', or 'Unsupported'.
    """
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        ) as k:
            val, _ = winreg.QueryValueEx(k, "UEFISecureBootEnabled")
            return "Enabled" if int(val) == 1 else "Disabled"
    except FileNotFoundError:
        # Key absent = Legacy BIOS / Secure Boot not supported
        return "Unsupported"
    except PermissionError:
        # Can still confirm UEFI presence via PlatformKey subkey
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\SecureBoot\PlatformKey"
            ):
                return "Disabled"
        except Exception:
            pass
        return "Unknown"
    except Exception:
        return "Unknown"


def _detect_tpm():
    """Detect TPM presence and version via registry without admin privileges.
    Checks HKLM\\SYSTEM\\CurrentControlSet\\Enum\\ACPI for known TPM hardware
    IDs, then falls back to HKLM\\SOFTWARE\\Microsoft\\Tpm and the TPM
    driver service key.
    Returns a version string: '2.0', '1.2', 'Present', or '' (not found).
    """
    # 1. Enumerate Enum\ACPI for TPM device nodes
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Enum\ACPI"
        ) as acpi:
            num_devs = winreg.QueryInfoKey(acpi)[0]
            for idx in range(num_devs):
                try:
                    dev_id = winreg.EnumKey(acpi, idx).upper()
                except Exception:
                    continue
                if dev_id in _TPM2_ACPI_IDS:
                    return "2.0"
                if dev_id in _TPM1_ACPI_IDS:
                    return "1.2"
                # Generic: any ACPI ID containing "TPM" — dig into HardwareID for version
                if "TPM" in dev_id:
                    try:
                        with winreg.OpenKey(acpi, dev_id) as dev_key:
                            inst_count = winreg.QueryInfoKey(dev_key)[0]
                            for j in range(inst_count):
                                try:
                                    inst = winreg.EnumKey(dev_key, j)
                                    with winreg.OpenKey(dev_key, inst) as inst_key:
                                        hw_ids, _ = winreg.QueryValueEx(inst_key, "HardwareID")
                                        hw_str = " ".join(
                                            hw_ids if isinstance(hw_ids, (list, tuple))
                                            else [str(hw_ids)]
                                        ).upper()
                                        if "2.0" in hw_str or "TPM20" in hw_str:
                                            return "2.0"
                                        if "1.2" in hw_str or "TPM12" in hw_str:
                                            return "1.2"
                                except Exception:
                                    continue
                    except Exception:
                        pass
                    return "Present"
    except Exception:
        pass

    # 2. Fallback: HKLM\SOFTWARE\Microsoft\Tpm
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Tpm"
        ) as tpm_key:
            for val_name in ("SpecVersion", "ManufacturerVersion"):
                try:
                    spec, _ = winreg.QueryValueEx(tpm_key, val_name)
                    spec_str = str(spec)
                    if "2.0" in spec_str:
                        return "2.0"
                    if "1.2" in spec_str:
                        return "1.2"
                except Exception:
                    continue
            return "Present"  # Key exists but no version value readable
    except Exception:
        pass

    # 3. Last resort: TPM driver service registered?
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\TPM"
        ):
            return "Present"
    except Exception:
        pass

    return ""  # Not found


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

def _version_tuple(version_text):
    """Convert version text like 'v1.3.2' or 'SystemShield-v1.3.2' into a tuple."""
    try:
        m = _re.search(r"(\d+(?:\.\d+){0,3})", str(version_text or ""))
        if not m:
            return ()
        return tuple(int(part) for part in m.group(1).split("."))
    except Exception:
        return ()


@eel.expose
def get_app_info():
    """Return local app metadata for the About page."""
    return {
        "name": "WebGeeks SystemShield",
        "version": VERSION,
        "repo_url": "https://github.com/ImmaGundam/WebGeeks-SystemShield",
        "release_url": "https://github.com/ImmaGundam/WebGeeks-SystemShield/releases/latest",
        "website_url": "https://systemshield.net/"
    }


@eel.expose
def check_for_updates():
    """Compare local VERSION against the latest GitHub release tag."""
    api_url = "https://api.github.com/repos/ImmaGundam/WebGeeks-SystemShield/releases/latest"
    try:
        req = urllib.request.Request(
            api_url,
            headers={
                "User-Agent": f"SystemShield/{VERSION}",
                "Accept": "application/vnd.github+json"
            }
        )
        with urllib.request.urlopen(req, timeout=12) as response:
            data = json.loads(response.read().decode())

        latest_version = str(data.get("tag_name") or data.get("name") or "").lstrip("v")
        release_url = data.get("html_url") or "https://github.com/ImmaGundam/WebGeeks-SystemShield/releases/latest"
        assets = data.get("assets") or []
        preferred_asset = ""
        for asset in assets:
            name = str(asset.get("name") or "").lower()
            if name.endswith(".exe"):
                preferred_asset = asset.get("browser_download_url") or ""
                break
        if not preferred_asset and assets:
            preferred_asset = assets[0].get("browser_download_url") or ""

        local_parts = _version_tuple(VERSION)
        remote_parts = _version_tuple(latest_version)

        payload = {
            "version": VERSION,
            "current": VERSION,
            "latest": latest_version or "Unknown",
            "release_url": release_url,
            "download_url": preferred_asset,
            "published_at": data.get("published_at", ""),
        }

        if not remote_parts:
            payload.update({
                "status": "error",
                "message": "Latest release did not include a readable version tag."
            })
            return payload

        if remote_parts > local_parts:
            payload["status"] = "update_available"
            return payload

        if local_parts > remote_parts:
            payload["status"] = "ahead_of_release"
            payload["message"] = "Installed version is newer than the latest public GitHub release."
            return payload

        payload["status"] = "up_to_date"
        return payload

    except urllib.error.HTTPError as e:
        if getattr(e, "code", None) == 404:
            return {
                "status": "no_release",
                "version": VERSION,
                "current": VERSION,
                "latest": "Unknown",
                "release_url": "https://github.com/ImmaGundam/WebGeeks-SystemShield/releases",
                "message": "No published GitHub release was found."
            }
        return {
            "status": "error",
            "version": VERSION,
            "current": VERSION,
            "latest": "Unknown",
            "message": f"GitHub returned HTTP {getattr(e, 'code', 'error')}"
        }
    except Exception as e:
        return {
            "status": "error",
            "version": VERSION,
            "current": VERSION,
            "latest": "Unknown",
            "message": str(e)
        }

@eel.expose
def perform_scan():
    try:
        _progress("Starting system scan...", 0)

        results = {}
        results['detection_evidence'] = {
            'password_managers': {},
            'remote_software': {},
            'rmm_software': {},
        }
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

        # Secure Boot: registry-based, no admin required
        sb_state = _detect_secure_boot()

        # TPM: registry-based via Enum\ACPI + fallbacks, no admin required
        tpm_version = _detect_tpm()
        if tpm_version == "2.0":
            tpm_result = "Present (v2.0)"
        elif tpm_version == "1.2":
            tpm_result = "Present (v1.2)"
        elif tpm_version == "Present":
            tpm_result = "Present"
        else:
            tpm_result = "Not Found"

        vbs_status = ps_first([
            "try { (Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard).VirtualizationBasedSecurityStatus.ToString() } catch { '0' }"
        ])

        results['os_security'] = {
            "secure_boot": "Enabled" if sb_state == "Enabled" else "Disabled/Unsupported",
            "tpm": tpm_result,
            "vbs": "Running" if vbs_status.strip() == "2" else "Off"
        }

        if sb_state != "Enabled":
            risk_count += 1

        if tpm_version == "":
            risk_count += 1

        if vbs_status.strip() != "2":
            risk_count += 1

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
                        r"manage-bde -status C: 2>$null | Select-String 'Encryption Method' | ForEach-Object { ($_ -split ':\s*',2)[1].Trim() }",
                        "try{(Get-BitLockerVolume -MountPoint C: -ErrorAction Stop).EncryptionMethod}catch{}",
                    ])
                    if enc_method_raw and enc_method_raw != "Not Detected" and len(enc_method_raw) < 80 and "Exception" not in enc_method_raw and "Access denied" not in enc_method_raw:
                        enc_method = enc_method_raw
                    enc_ver_raw = ps_first([
                        r"manage-bde -status C: 2>$null | Select-String 'Version' | Select-Object -First 1 | ForEach-Object { ($_ -split ':\s*',2)[1].Trim() }",
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
        
        # Check screensaver + password protection via winreg (no admin needed)
        _TIMEOUT_NONE = {"0x00000000", "0", "", "Not Detected"}
        screensaver_locked = False
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop") as _dsk:
                def _qv(k, n):
                    try: return winreg.QueryValueEx(k, n)[0]
                    except: return None
                _ss_active  = _qv(_dsk, "ScreenSaveActive")
                _ss_secure  = _qv(_dsk, "ScreenSaverIsSecure")
                _ss_timeout = _qv(_dsk, "ScreenSaveTimeOut")
            if str(_ss_active) == "1" and str(_ss_secure) == "1":
                try:
                    screensaver_locked = int(_ss_timeout) > 0
                except Exception:
                    screensaver_locked = True
        except Exception:
            pass

        # Display off timeout — "Turn off display after" (VIDEOIDLE).
        # NOTE: the old check used VIDEOCONLOCK which is how long the display stays on
        # AFTER locking — not the lock trigger itself. A value of 0 (off immediately
        # when locked) is correct behaviour, not a sign that lock screen is disabled.
        display_timeout_raw = get_ps(
            "powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE | "
            "Select-String 'Current AC Power Setting Index' | "
            "ForEach-Object { ($_ -split ':')[1].Trim() }"
        ).strip()

        # System sleep timeout
        sleep_timeout_raw = get_ps(
            "powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE | "
            "Select-String 'Current AC Power Setting Index' | "
            "ForEach-Object { ($_ -split ':')[1].Trim() }"
        ).strip()

        display_timeout_set = display_timeout_raw not in _TIMEOUT_NONE
        sleep_enabled = sleep_timeout_raw not in _TIMEOUT_NONE

        # Lock screen is active if screensaver+password is configured, OR if the
        # display/system sleep auto-off is set (modern Windows requires sign-in on wake)
        lock_enabled = screensaver_locked or display_timeout_set or sleep_enabled
        
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
        
        # Check account type: Microsoft Account / Domain Account / Local Account
        ms_account = ps_first([
            "Get-ItemPropertyValue -Path 'HKCU:\\Software\\Microsoft\\IdentityStore\\Cache\\*\\IdentityCache\\*' -Name UserName -ErrorAction SilentlyContinue 2>$null | Select-Object -First 1",
            "Write-Output ''"
        ])
        domain_joined = get_ps("(Get-CimInstance Win32_ComputerSystem).PartOfDomain")
        if "@" in ms_account:
            account_type = "Microsoft Account"
        elif "True" in domain_joined:
            account_type = "Domain Account"
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
        
        # Browser metadata loaded from detection_lists.py

        # Registry paths for browser detection loaded from detection_lists.py
        browser_registry = BROWSER_REGISTRY
        
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
        
        # Browser executable paths loaded from detection_lists.py
        browser_exe_paths = BROWSER_EXE_PATHS
        
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

        # CPUs — enumerate all physical processors, primary (CPU0) first
        _cpu_raw = get_ps("Get-CimInstance Win32_Processor | Select-Object Name, DeviceID | ConvertTo-Json")
        try:
            _cpu_json = json.loads(_cpu_raw)
            if isinstance(_cpu_json, dict):
                _cpu_json = [_cpu_json]
            _cpu_json.sort(key=lambda x: str(x.get('DeviceID', 'CPU9')))
            results['cpus'] = [c.get('Name', 'Unknown').strip() for c in _cpu_json if c.get('Name')]
            results['cpu'] = results['cpus'][0] if results['cpus'] else 'Unknown'
        except Exception:
            _fb_cpu = get_ps("(Get-CimInstance Win32_Processor | Select-Object -First 1).Name")
            results['cpus'] = [_fb_cpu] if _fb_cpu and _fb_cpu != 'Not Detected' else ['Unknown']
            results['cpu'] = results['cpus'][0]

        results['motherboard'] = get_ps("(Get-CimInstance Win32_BaseBoard).Product")
        mobo_manufacturer = get_ps("(Get-CimInstance Win32_BaseBoard).Manufacturer")
        if mobo_manufacturer and mobo_manufacturer != "Not Detected":
            results['motherboard'] = f"{mobo_manufacturer} {results['motherboard']}"

        # RAM info
        ram_total = get_ps("[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)")
        ram_speed = get_ps("(Get-CimInstance Win32_PhysicalMemory | Select-Object -First 1).Speed")
        results['ram'] = f"{ram_total} GB" + (f" @ {ram_speed} MHz" if ram_speed and ram_speed != "Not Detected" else "")

        # GPUs — discrete (NVIDIA/AMD) first, integrated Intel second, virtual/software last
        _gpu_raw = get_ps(
            "Get-CimInstance Win32_VideoController | "
            "Select-Object Name,CurrentHorizontalResolution,CurrentVerticalResolution,AdapterRAM,DriverVersion,DriverDate,CurrentRefreshRate,VideoProcessor | ConvertTo-Json"
        )
        try:
            _gpu_json = json.loads(_gpu_raw)
            if isinstance(_gpu_json, dict):
                _gpu_json = [_gpu_json]
            def _gpu_pri(g):
                n = (g.get('Name') or '').lower()
                if any(k in n for k in ['microsoft', 'basic render', 'remote desktop', 'virtual', 'hyper-v']):
                    return 3
                if 'intel' in n:
                    return 2
                return 1
            _gpu_json.sort(key=_gpu_pri)
            nvidia_details = _get_nvidia_smi_details()
            results['gpus'] = []
            for _idx, _g in enumerate(_gpu_json):
                _gn = (_g.get('Name') or '').strip()
                if _gn:
                    _w, _h = _g.get('CurrentHorizontalResolution'), _g.get('CurrentVerticalResolution')
                    vendor = _gpu_vendor(_gn)
                    adapter_ram = _gb_from_bytes(_g.get('AdapterRAM'))
                    driver_version = _clean_detected(_g.get('DriverVersion'))
                    gpu_clock = "Undetected"
                    memory_clock = "Undetected"
                    telemetry_source = "Windows WMI"
                    if vendor == "NVIDIA" and nvidia_details:
                        match = None
                        for nd in nvidia_details:
                            nd_name = nd.get('name', '')
                            if nd_name and (nd_name.lower() in _gn.lower() or _gn.lower() in nd_name.lower()):
                                match = nd
                                break
                        if match is None and _idx < len(nvidia_details):
                            match = nvidia_details[_idx]
                        if match:
                            adapter_ram = match.get('adapter_ram') or adapter_ram
                            driver_version = match.get('driver_version') or driver_version
                            gpu_clock = match.get('gpu_clock') or gpu_clock
                            memory_clock = match.get('memory_clock') or memory_clock
                            telemetry_source = match.get('telemetry_source') or telemetry_source
                    refresh = _clean_detected(_g.get('CurrentRefreshRate'))
                    results['gpus'].append({
                        'name': _gn,
                        'vendor': vendor,
                        'resolution': f"{_w}x{_h}" if _w and _h else '',
                        'memory': adapter_ram,
                        'driver_version': driver_version,
                        'gpu_clock': gpu_clock,
                        'memory_clock': memory_clock,
                        'refresh_rate': f"{refresh} Hz" if refresh != "Undetected" else "Undetected",
                        'video_processor': _clean_detected(_g.get('VideoProcessor')),
                        'telemetry_source': telemetry_source,
                    })
        except Exception:
            results['gpus'] = []

        # Non-admin hardware/system specification summary for Dashboard Hardware Profile.
        hardware_profile = _collect_hardware_profile()
        results['hardware_profile'] = hardware_profile
        results['system_manufacturer'] = hardware_profile.get('system_manufacturer', 'Undetected')
        results['system_model'] = hardware_profile.get('system_model', 'Undetected')
        results['device_type'] = hardware_profile.get('device_type', 'Undetected')
        results['storage_devices'] = hardware_profile.get('storage_devices', [])
        results['memory_module_count'] = hardware_profile.get('memory_module_count', 'Undetected')
        results['memory_manufacturers'] = hardware_profile.get('memory_manufacturers', 'Undetected')
        results['uptime'] = hardware_profile.get('uptime', 'Undetected')
        results['uptime_seconds'] = hardware_profile.get('uptime_seconds', 0)
        results['uptime_status'] = hardware_profile.get('uptime_status', 'good')
        results['processors'] = hardware_profile.get('processors', [])
        results['power_profile_name'] = hardware_profile.get('power_profile_name', 'Undetected')
        results['power_profile_guid'] = hardware_profile.get('power_profile_guid', 'Undetected')

        if results['uptime_status'] == 'risk':
            risk_count += 1
        elif results['uptime_status'] == 'caution':
            caution_count += 1

        # ---------------- PASSWORD MANAGERS ----------------
        _progress("Checking password managers...", 95)
        password_managers = []
        # Password manager detection loaded from detection_lists.py
        pm_detection = PM_DETECTION
        
        for name, reg_paths, exe_paths in pm_detection:
            found, evidence = _match_registry_or_paths(reg_paths, exe_paths)
            if found:
                password_managers.append(name)
                results['detection_evidence']['password_managers'][name] = evidence
                # Password managers are normally beneficial security tools.
                # Keep them visible, but do not count them as a risk by default.
        
        results['password_managers'] = password_managers

        # ---------------- REMOTE SOFTWARE (RISK) ----------------
        _progress("Checking remote access software...", 98)
        remote_software = []
        # Remote-access software detection loaded from detection_lists.py
        rs_detection = RS_DETECTION
        
        for name, reg_paths, exe_paths in rs_detection:
            found, evidence = _match_registry_or_paths(reg_paths, exe_paths)
            if found:
                remote_software.append(name)
                results['detection_evidence']['remote_software'][name] = evidence
                risk_count += 1
        
        results['remote_software'] = remote_software

        # ---------------- RMM PLATFORMS ----------------
        _progress("Checking RMM platforms...", 99)
        rmm_software = []
        for name, reg_paths, exe_paths in RMM_DETECTION:
            found, evidence = _match_registry_or_paths(reg_paths, exe_paths)
            if found:
                rmm_software.append(name)
                results['detection_evidence']['rmm_software'][name] = evidence
                caution_count += 1

        results['rmm_software'] = rmm_software

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

        # Check Windows Recovery Environment (WinRE)
        _winre_result = "Unknown"

        # Method 1: reagentc /info - most reliable when it works
        _winre_raw = get_ps(
            "try { $o = reagentc /info 2>&1 | Out-String; if ($o -match 'Windows RE status[^:]*:\\s*(\\S+)') { $Matches[1] } elseif ($o -match 'Enabled') { 'Enabled' } elseif ($o -match 'Disabled') { 'Disabled' } else { '' } } catch { '' }"
        )
        if _winre_raw and _winre_raw.strip() not in ("", "Not Detected"):
            _s = _winre_raw.strip().lower()
            if "enabled" in _s:
                _winre_result = "Enabled"
            elif "disabled" in _s:
                _winre_result = "Disabled"

        # Method 2: BCD store - check for WinRE partition entry
        if _winre_result == "Unknown":
            _bcd_raw = get_ps(
                "try { $b = bcdedit /enum all 2>&1 | Out-String; if ($b -match 'Windows Recovery Environment') { 'Found' } else { '' } } catch { '' }"
            )
            if _bcd_raw and "Found" in _bcd_raw:
                _winre_result = "Enabled"

        # Method 3: WinREAgent registry key
        if _winre_result == "Unknown":
            _wr_val = read_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\WinREAgent",
                "Disabled"
            )
            if _wr_val is None:
                # Key exists but Disabled value absent = WinRE enabled (default Win10/11 state)
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SYSTEM\CurrentControlSet\Control\WinREAgent"
                    ):
                        _winre_result = "Enabled"
                except Exception:
                    pass
            elif int(_wr_val) == 1:
                _winre_result = "Disabled"
            else:
                _winre_result = "Enabled"

        # Method 4: Check if WinRE partition exists on any disk (DISKPART/WMI)
        if _winre_result == "Unknown":
            _part_raw = get_ps(
                "try { Get-Partition | Where-Object { $_.Type -eq 'Recovery' } | Measure-Object | Select-Object -ExpandProperty Count } catch { '0' }"
            )
            if _part_raw and _part_raw.strip() not in ("", "0", "Not Detected"):
                _winre_result = "Enabled"

        # Method 5: Windows 10/11 default - if all methods fail, presence of
        # C:\Windows\System32\Recovery\Winre.wim means WinRE files are present
        if _winre_result == "Unknown":
            _wim_paths = [
                r"C:\Windows\System32\Recovery\Winre.wim",
                r"C:\Recovery\WindowsRE\Winre.wim",
            ]
            for _wp in _wim_paths:
                if os.path.exists(_wp):
                    _winre_result = "Enabled"
                    break

        results['windows_recovery'] = _winre_result

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
            "rmm_software": [],
            "cpu": "Unknown",
            "cpus": [],
            "gpus": [],
            "motherboard": "Unknown",
            "ram": "Unknown",
            "hardware_profile": {"system_manufacturer": "Undetected", "system_model": "Undetected", "device_type": "Undetected", "storage_devices": [], "memory_module_count": "Undetected", "memory_manufacturers": "Undetected", "uptime": "Undetected", "uptime_seconds": 0, "uptime_status": "good", "processors": [], "power_profile_name": "Undetected", "power_profile_guid": "Undetected"},
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
            "windows_recovery": "Unknown"
        }

# Known Windows/System publishers for source classification (loaded from detection_lists.py)
_SYSTEM_PUBLISHERS = SYSTEM_PUBLISHERS

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
            version_str = (entry.get("DisplayVersion") or "").strip()
            progs.append({"name": name, "size": mb, "publisher": pub, "source": source, "uninstall": uninstall_str, "version": version_str})
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
        # Bad software list loaded from detection_lists.py
        def _name_hits(prog_list, keyword_list):
            """Return program names that match any keyword in keyword_list."""
            hits = []
            for p in prog_list:
                for kw in keyword_list:
                    if kw.lower() in p['name'].lower():
                        hits.append(p['name'])
                        break
            return hits

        threat_lists = [
            ("bad_software",        BAD_SOFTWARE),
            ("scamware",            SCAMWARE),
            ("torrent_clients",     TORRENT_CLIENTS),
            ("crypto_miners",       CRYPTO_MINERS),
            ("hacking_utils",       HACKING_UTILS),
            ("data_exfil_tools",    DATA_EXFIL_TOOLS),
            ("remote_shell_tools",  REMOTE_SHELL_TOOLS),
            ("rat_tools",           RAT_TOOLS),
            ("credential_stealers", CREDENTIAL_STEALERS),
        ]
        threat_results = {key: _name_hits(progs, lst) for key, lst in threat_lists}
        # Keep legacy bad_software key for frontend compatibility
        bad_hits = threat_results["bad_software"]

        # Version-aware WinRAR check — only flag versions below 7.13
        # (CVE-2025-8088 CVSS 8.4 / CVE-2025-6218 CVSS 7.8 are fixed in 7.13+)
        WINRAR_SAFE_VERSION = (7, 13)
        for p in progs:
            if "winrar" in p["name"].lower():
                ver_str = p.get("version", "")
                try:
                    parts = tuple(int(x) for x in ver_str.split(".") if x.isdigit())[:2]
                    if parts and parts < WINRAR_SAFE_VERSION:
                        bad_hits.append(p["name"])
                except Exception:
                    # Version unparseable — flag it to be safe
                    bad_hits.append(p["name"])

        return {
            "programs": progs,
            "total_program_size": f"{round(total_mb / 1024.0, 2)} GB",
            "program_count": len(progs),
            # Legacy key (PUP / bloatware) - kept for frontend compatibility
            "bad_software": bad_hits,
            # Extended threat categories
            "scamware":            threat_results["scamware"],
            "torrent_clients":     threat_results["torrent_clients"],
            "crypto_miners":       threat_results["crypto_miners"],
            "hacking_utils":       threat_results["hacking_utils"],
            "data_exfil_tools":    threat_results["data_exfil_tools"],
            "remote_shell_tools":  threat_results["remote_shell_tools"],
            "rat_tools":           threat_results["rat_tools"],
            "credential_stealers": threat_results["credential_stealers"],
            "size_breakdown": {
                "system_size": f"{round(system_mb / 1024.0, 2)} GB",
                "user_size":   f"{round(user_mb  / 1024.0, 2)} GB",
                "store_size":  f"{round(store_mb  / 1024.0, 2)} GB",
                "system_mb": round(system_mb, 2),
                "user_mb":   round(user_mb,   2),
                "store_mb":  round(store_mb,  2)
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

# KNOWN_BAD_DNS and VPN_DETECTION loaded from detection_lists.py


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

        # --- Interface dumping / packet capture software detection (list from detection_lists.py) ---
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

        # --- SSH server / Telnet feature detection ---
        # ssh_server_status reflects the actual Windows service state:
        #   'Running'  - actively accepting connections (flag as risk)
        #   'Stopped'  - installed but not running (informational only)
        #   'Disabled' - installed but disabled (informational only)
        #   'Not Installed' - OpenSSH server feature not present
        try:
            ssh_svc_status = get_ps(
                "Get-Service sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"
            )
            ssh_svc_start = get_ps(
                "Get-Service sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty StartType"
            )
            if not ssh_svc_status or ssh_svc_status in ('Not Detected', ''):
                result['ssh_server_status'] = 'Not Installed'
            else:
                result['ssh_server_status'] = ssh_svc_status  # Running / Stopped / Disabled etc.
            result['ssh_server_start_type'] = ssh_svc_start if ssh_svc_start not in ('Not Detected', '', None) else 'Unknown'
            # Legacy bool key — only True when the service is actually Running
            result['ssh_server_enabled'] = (ssh_svc_status == 'Running')
        except Exception:
            result['ssh_server_status'] = 'Unknown'
            result['ssh_server_start_type'] = 'Unknown'
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

# VirusTotal API keys are session-only.
# SystemShield does not save or remove API keys and does not create
# a VirusTotal config file. The UI passes the key directly into each
# lookup call for the current session only.


@eel.expose
def vt_pick_and_scan_file(api_key=""):
    """Open a file picker dialog and scan the selected file on VirusTotal."""
    try:
        api_key = (api_key or "").strip()
        if not api_key:
            return {"error": "Enter your VirusTotal API key to use file scan."}

        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        filepath = filedialog.askopenfilename(title="Select file to scan on VirusTotal")
        root.destroy()
        if not filepath:
            return {"error": "No file selected"}
        return vt_scan_file(filepath, api_key)
    except Exception as e:
        return {"error": str(e)}


@eel.expose
def vt_scan_file(filepath, api_key=""):
    """Upload a file to VirusTotal for scanning. Returns scan results or ID."""
    try:
        api_key = (api_key or "").strip()
        if not api_key:
            return {"error": "Enter your VirusTotal API key to use file scan."}
        if not os.path.exists(filepath):
            return {"error": "File not found"}

        # First check if hash is already known.
        sha256 = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
        result = vt_check_hash(sha256, api_key)
        if result and not result.get('error') and result.get("found") is not False:
            return result

        # Upload file only when the hash is not already known.
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
def vt_check_hash(hash_val, api_key=""):
    """Look up a file hash on VirusTotal."""
    try:
        api_key = (api_key or "").strip()
        if not api_key:
            return {"error": "Enter your VirusTotal API key to use hash lookup."}
        hash_val = (hash_val or "").strip()
        if not hash_val:
            return {"error": "Enter a SHA-256, SHA-1, or MD5 hash."}

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
            "cpus": scan_data.get('cpus', []),
            "gpus": scan_data.get('gpus', []),
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
        "windows_recovery": scan_data.get('windows_recovery', 'Unknown'),
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
    # The PDF program list uses the Apps & Programs page's current sort order.
    # Default export is the first 30 programs; optional all-program export can be enabled from the UI.
    if programs_data:
        _all_progs = programs_data.get('programs') or []
        _export_all = bool(programs_data.get('pdf_export_all', False))
        _display_limit = len(_all_progs) if _export_all else 30
        _display_progs = _all_progs[:_display_limit]
        _by_size = sorted(
            [p for p in _all_progs if (p.get('size') or 0) > 0],
            key=lambda x: x.get('size', 0), reverse=True
        )

        def _program_line(p):
            _name = str(p.get('name', 'Unknown'))
            _size = (str(p.get('size')) + ' MB') if p.get('size') else '-'
            return _name + ' (' + _size + ')'

        summary['programs'] = {
            "program_count": programs_data.get('program_count', 0),
            "total_size": programs_data.get('total_program_size', '0 GB'),
            "size_breakdown": programs_data.get('size_breakdown', {}),
            "bad_software": programs_data.get('bad_software', []),
            "export_all": _export_all,
            "export_order": programs_data.get('pdf_export_order', 'current'),
            "display_count": len(_display_progs),
            "display_programs": [_program_line(p) for p in _display_progs],
            "top_programs": [_program_line(p) for p in _all_progs[:30]],
            "top10_by_size": [{'name': p['name'], 'size': p.get('size', 0)} for p in _by_size[:10]],
            "all_programs": [{'name': p['name'], 'size': p.get('size', 0)} for p in _all_progs],
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
def open_uac_settings():
    """Open UAC (User Account Control) settings dialog."""
    try:
        subprocess.Popen(["UserAccountControlSettings.exe"], shell=True)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def open_netplwiz():
    """Open netplwiz (manage user accounts and auto-login)."""
    try:
        subprocess.Popen(["netplwiz"], shell=True)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def open_computer_management():
    """Open Computer Management (manage local users and groups)."""
    try:
        subprocess.Popen(["compmgmt.msc"], shell=True)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def open_ms_settings(page):
    """Open a specific Windows Settings page or security tool by key name."""
    _DESTINATIONS = {
        "signin":     "ms-settings:signinoptions",
        "lockscreen": "ms-settings:lockscreen",
        "powersleep": "ms-settings:powersleep",
        "encryption": "ms-settings:deviceencryption",
        "defender":   "windowsdefender://",
        "firewall":   "ms-settings:windowsdefender",
        "apps":       "ms-settings:appsfeatures",
        "windows_update": "ms-settings:windowsupdate",
        "network":    "ms-settings:network-status",
        "vpn":        "ms-settings:network-vpn",
        "proxy":      "ms-settings:network-proxy",
        "remote_desktop": "ms-settings:remotedesktop",
        "recovery":   "ms-settings:recovery",
    }
    uri = _DESTINATIONS.get(page)
    if not uri:
        return {"status": "error", "message": f"Unknown settings page: {page}"}
    try:
        os.startfile(uri)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@eel.expose
def uninstall_program(program_name):
    """Run a program's Windows-registered uninstaller by name.

    SystemShield does not delete files, remove registry keys, stop
    services, or perform custom cleanup. It only opens the uninstall
    command registered by Windows for the matching installed program.
    """
    try:
        target = (program_name or "").strip()
        if not target:
            return {"status": "error", "message": "No program name was provided."}

        for entry in enumerate_uninstall_entries():
            dname = (entry.get('DisplayName') or '').strip()
            if not dname:
                continue

            if target.lower() in dname.lower():
                uninstall_str = (entry.get('UninstallString') or '').strip()
                if uninstall_str:
                    subprocess.Popen(uninstall_str, shell=True)
                    return {"status": "ok", "message": f"Uninstaller opened for {dname}."}

                return {
                    "status": "error",
                    "message": f"No registered uninstaller was found for {dname}."
                }

        return {
            "status": "error",
            "message": f"No registered uninstaller was found for {target}."
        }
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


# ==================== TITLEBAR THEMING (DWM) ====================
# Version 1.3.2 UI polish:
# Keep the normal Windows title bar, but tint it to match the SystemShield theme.
# This is cosmetic only. It does not change scanner/remediation behavior.
# DWMWA_USE_IMMERSIVE_DARK_MODE  -> white title text/buttons on dark caption color
# DWMWA_CAPTION_COLOR            -> exact caption background color on Windows 11+
_DWMWA_DARK_MODE   = 20
_DWMWA_CAPTION_COL = 35

# COLORREF = 0x00BBGGRR
# Sidebar light #212f4d -> B=4D G=2F R=21 -> 0x004D2F21
# Sidebar dark  #111318 -> B=18 G=13 R=11 -> 0x00181311
_TB_COLOR_LIGHT = 0x004D2F21
_TB_COLOR_DARK  = 0x00181311


def _find_systemshield_windows():
    """Return visible top-level window handles whose title contains SystemShield.

    Uses ctypes instead of requiring pywin32 so the title bar theming still works
    in portable/compiled builds where optional win32gui imports are unavailable.
    """
    hwnds = []
    try:
        import ctypes
        user32 = ctypes.WinDLL('user32', use_last_error=True)

        EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def _callback(hwnd, _lparam):
            try:
                if not user32.IsWindowVisible(hwnd):
                    return True
                length = user32.GetWindowTextLengthW(hwnd)
                if length <= 0:
                    return True
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buff, length + 1)
                title = buff.value or ''
                if 'SystemShield' in title:
                    hwnds.append(hwnd)
            except Exception:
                pass
            return True

        user32.EnumWindows(EnumWindowsProc(_callback), 0)
    except Exception:
        pass
    return hwnds


def _apply_titlebar_color(use_dark=False):
    """Set the native Windows title bar color to match the app theme.

    Light mode uses the sidebar blue. Dark mode uses the darker sidebar color.
    The title bar uses dark-caption mode in both themes so the title text and
    window controls remain readable against the dark branded colors.
    """
    try:
        import ctypes
        dwmapi = ctypes.WinDLL('dwmapi')
        color = _TB_COLOR_DARK if use_dark else _TB_COLOR_LIGHT

        for hwnd in _find_systemshield_windows():
            # Dark-caption mode gives white text/buttons against the dark app colors.
            dark_val = ctypes.c_int(1)
            try:
                dwmapi.DwmSetWindowAttribute(hwnd, _DWMWA_DARK_MODE,
                                             ctypes.byref(dark_val), ctypes.sizeof(dark_val))
            except Exception:
                pass

            # Exact caption tint. Windows 11 supports this; unsupported systems ignore it.
            color_val = ctypes.c_int(color)
            try:
                dwmapi.DwmSetWindowAttribute(hwnd, _DWMWA_CAPTION_COL,
                                             ctypes.byref(color_val), ctypes.sizeof(color_val))
            except Exception:
                pass
    except Exception:
        pass  # Non-critical cosmetic fallback


@eel.expose
def set_titlebar_theme(use_dark):
    """Called from JS theme toggle to keep the Windows title bar in sync."""
    _apply_titlebar_color(use_dark=bool(use_dark))


def _startup_titlebar():
    """Retry briefly while the Edge/Eel window is being created."""
    import time
    for _ in range(12):
        time.sleep(0.5)
        _apply_titlebar_color(use_dark=False)


threading.Thread(target=_startup_titlebar, daemon=True).start()

eel.start(
    'index.html',
    mode='edge',
    size=(1150, 950),
    port=0,
    cmdline_args=[
        '--new-window',
    ]
)
