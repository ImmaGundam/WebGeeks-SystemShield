# scan_helpers.py - scan helper module
# Purpose: Provide reusable Windows security, storage, and hardware detection helpers.

import re as re_module
import time

import psutil
import winreg

from core.system_utils import (
    _clean_detected,
    _device_type_from_chassis,
    _format_cache_kb,
    _format_uptime,
    _gb_from_bytes,
    _json_as_list,
    _mhz,
    get_ps,
)


TPM2_ACPI_IDS = frozenset(
    {
        "MSFT0101",
        "IFX0102",
        "INTC0101",
        "NTZ0101",
        "CSCO0101",
        "ATML0201",
        "STM0201",
    }
)

TPM1_ACPI_IDS = frozenset(
    {
        "IFX0101",
        "BCM0101",
        "ATML0100",
        "STM0100",
        "NSC0100",
    }
)


def collect_hardware_profile():
    """Collect non-admin hardware inventory values for dashboard profile."""
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

    cs = _json_as_list(
        get_ps(
            "Get-CimInstance Win32_ComputerSystem | "
            "Select-Object Manufacturer,Model | ConvertTo-Json"
        )
    )
    if cs:
        profile["system_manufacturer"] = _clean_detected(cs[0].get("Manufacturer"))
        profile["system_model"] = _clean_detected(cs[0].get("Model"))

    enc = _json_as_list(
        get_ps(
            "Get-CimInstance Win32_SystemEnclosure | "
            "Select-Object ChassisTypes | ConvertTo-Json"
        )
    )
    chassis = enc[0].get("ChassisTypes") if enc else []
    profile["device_type"] = _device_type_from_chassis(
        chassis, profile["system_manufacturer"], profile["system_model"]
    )

    processors = _json_as_list(
        get_ps(
            "Get-CimInstance Win32_Processor | "
            "Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,CurrentClockSpeed,L2CacheSize,L3CacheSize,SocketDesignation | ConvertTo-Json"
        )
    )
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
        if (
            name
            == manufacturer
            == cores
            == threads
            == max_clock
            == current_clock
            == l2
            == l3
            == socket
            == "Undetected"
        ):
            continue
        profile["processors"].append(
            {
                "name": name,
                "manufacturer": manufacturer,
                "cores": cores,
                "threads": threads,
                "max_clock": max_clock,
                "current_clock": current_clock,
                "l2_cache": l2,
                "l3_cache": l3,
                "socket": socket,
            }
        )

    power_raw = get_ps("powercfg /getactivescheme")
    if power_raw and power_raw != "Not Detected":
        try:
            match = re_module.search(
                r"Power Scheme GUID:\s*([a-fA-F0-9\-]+)\s*(?:\((.*?)\))?",
                power_raw,
            )
            if match:
                profile["power_profile_guid"] = match.group(1) or "Undetected"
                profile["power_profile_name"] = _clean_detected(match.group(2))
            else:
                profile["power_profile_name"] = _clean_detected(power_raw)
        except Exception:
            profile["power_profile_name"] = _clean_detected(power_raw)

    mem = _json_as_list(
        get_ps(
            "Get-CimInstance Win32_PhysicalMemory | "
            "Select-Object Manufacturer,Capacity,Speed | ConvertTo-Json"
        )
    )
    if mem:
        profile["memory_module_count"] = str(len(mem))
        manufacturers = []
        for module in mem:
            mf = _clean_detected(module.get("Manufacturer"))
            if mf != "Undetected" and mf not in manufacturers:
                manufacturers.append(mf)
        profile["memory_manufacturers"] = ", ".join(manufacturers) if manufacturers else "Undetected"

    disks = _json_as_list(
        get_ps(
            "Get-CimInstance Win32_DiskDrive | "
            "Select-Object Model,Manufacturer,MediaType,InterfaceType,Size | ConvertTo-Json"
        )
    )
    for disk in disks:
        model = _clean_detected(disk.get("Model"))
        manufacturer = _clean_detected(disk.get("Manufacturer"))
        media_type = _clean_detected(disk.get("MediaType"))
        interface_type = _clean_detected(disk.get("InterfaceType"))
        size = _gb_from_bytes(disk.get("Size"))
        if model == manufacturer == media_type == interface_type == size == "Undetected":
            continue
        profile["storage_devices"].append(
            {
                "model": model,
                "manufacturer": manufacturer,
                "media_type": media_type,
                "interface": interface_type,
                "size": size,
            }
        )

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


def detect_secure_boot():
    """Detect Secure Boot state via registry without admin privileges."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        ) as key:
            value, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
            return "Enabled" if int(value) == 1 else "Disabled"
    except FileNotFoundError:
        return "Unsupported"
    except PermissionError:
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecureBoot\PlatformKey"
            ):
                return "Disabled"
        except Exception:
            pass
        return "Unknown"
    except Exception:
        return "Unknown"


def detect_tpm():
    """Detect TPM presence/version via registry without admin privileges."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\ACPI") as acpi:
            num_devs = winreg.QueryInfoKey(acpi)[0]
            for idx in range(num_devs):
                try:
                    dev_id = winreg.EnumKey(acpi, idx).upper()
                except Exception:
                    continue
                if dev_id in TPM2_ACPI_IDS:
                    return "2.0"
                if dev_id in TPM1_ACPI_IDS:
                    return "1.2"
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
                                            hw_ids if isinstance(hw_ids, (list, tuple)) else [str(hw_ids)]
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

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Tpm") as tpm_key:
            for value_name in ("SpecVersion", "ManufacturerVersion"):
                try:
                    spec, _ = winreg.QueryValueEx(tpm_key, value_name)
                    spec_str = str(spec)
                    if "2.0" in spec_str:
                        return "2.0"
                    if "1.2" in spec_str:
                        return "1.2"
                except Exception:
                    continue
            return "Present"
    except Exception:
        pass

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\TPM"):
            return "Present"
    except Exception:
        pass

    return ""
