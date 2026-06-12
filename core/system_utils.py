# system_utils.py - system utility module
# Purpose: Provide shared PowerShell, registry, version, and hardware utility functions.

import glob
import json
import os
import re as _re
import subprocess
import winreg


try:
    import win32api  # type: ignore
    PYWIN32_AVAILABLE = True
except Exception:
    PYWIN32_AVAILABLE = False


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
    """Return ProductVersion for a Windows executable path using pywin32 if available."""
    if not path or not os.path.exists(path):
        return ""
    if PYWIN32_AVAILABLE:
        try:
            info = win32api.GetFileVersionInfo(path, "\\")
            ms = info["FileVersionMS"]
            ls = info["FileVersionLS"]
            return f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
        except Exception:
            pass
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
                            for field in (
                                "DisplayName",
                                "DisplayVersion",
                                "Publisher",
                                "InstallLocation",
                                "DisplayIcon",
                                "UninstallString",
                                "EstimatedSize",
                                "SystemComponent",
                            ):
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
    """Return passive detection evidence for configured registry keys and exe paths."""
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
            if "*" in exe_path:
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


def _version_tuple(version_text):
    """Convert version text like 'v1.2.3' or 'SystemShield-v1.2.3' into a tuple."""
    try:
        m = _re.search(r"(\d+(?:\.\d+){0,3})", str(version_text or ""))
        if not m:
            return ()
        return tuple(int(part) for part in m.group(1).split("."))
    except Exception:
        return ()
