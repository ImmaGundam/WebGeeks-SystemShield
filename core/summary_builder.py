# summary_builder.py - summary builder module
# Purpose: Build structured export summaries from scan, program, and network data.

from datetime import datetime


def build_summary(scan_data, programs_data=None, network_data=None):
    """Build a structured summary report from scan data with multi-page support."""
    summary = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system": {
            "user": scan_data.get("user", "Unknown"),
            "os": scan_data.get("os_caption", scan_data.get("os_name", "Unknown")),
            "build": scan_data.get("windows_build", "N/A"),
            "cpu": scan_data.get("cpu", "Unknown"),
            "cpus": scan_data.get("cpus", []),
            "gpus": scan_data.get("gpus", []),
            "ram": scan_data.get("ram", "Unknown"),
        },
        "risk_count": scan_data.get("risk_factor", 0),
        "caution_count": scan_data.get("caution_factor", 0),
        "issues": [],
    }

    checks = [
        (
            scan_data.get("os_security", {}).get("secure_boot") != "Enabled",
            "Secure Boot is disabled or unsupported",
            "Enable Secure Boot in BIOS/UEFI settings",
        ),
        (
            scan_data.get("os_security", {}).get("tpm", "").find("Present") < 0,
            "TPM not found",
            "Check BIOS settings for TPM enablement",
        ),
        (
            scan_data.get("os_security", {}).get("vbs") != "Running",
            "Core Isolation / VBS is off",
            "Enable Memory Integrity in Windows Security",
        ),
        (
            scan_data.get("drive_encryption") == "Not Encrypted",
            "Drive is not encrypted",
            "Enable BitLocker Drive Encryption",
        ),
        (
            scan_data.get("user_security", {}).get("is_admin") == "Yes",
            "Running as administrator",
            "Use a standard user account for daily tasks",
        ),
        (
            scan_data.get("user_security", {}).get("uac") != "Enabled",
            "UAC is disabled",
            "Enable UAC in Control Panel -> User Accounts",
        ),
        (
            scan_data.get("lock_security", {}).get("password_set") == "No",
            "No password set",
            "Set a password for your user account",
        ),
        (
            scan_data.get("lock_security", {}).get("lock_screen") == "Disabled",
            "Lock screen timeout disabled",
            "Enable screen lock in Settings -> Personalization -> Lock screen",
        ),
        (
            scan_data.get("auto_login") == "Enabled",
            "Auto-login enabled",
            "Disable automatic login",
        ),
        (
            scan_data.get("guest_account") == "Enabled",
            "Guest account enabled",
            "Disable the Guest account",
        ),
        (
            scan_data.get("defender_realtime") == "Disabled",
            "Defender real-time protection off",
            "Enable real-time protection in Windows Security",
        ),
        (
            not scan_data.get("av_details"),
            "No antivirus detected",
            "Install antivirus software",
        ),
        (
            not scan_data.get("fw_details", {}).get("windows_fw_enabled")
            and scan_data.get("fw_details", {}).get("third_party_count", 0) == 0,
            "No firewall active",
            "Enable Windows Firewall or install a firewall",
        ),
    ]
    for cond, desc, fix in checks:
        if cond:
            summary["issues"].append({"description": desc, "remediation": fix})

    for browser in scan_data.get("browsers", []):
        if browser.get("discontinued"):
            summary["issues"].append(
                {
                    "description": f"{browser['name']} is discontinued",
                    "remediation": "Uninstall and switch to a supported browser",
                }
            )
    for password_manager in scan_data.get("password_managers", []):
        summary["issues"].append(
            {
                "description": f"Password manager detected: {password_manager}",
                "remediation": "Evaluate if this is intentional; remove if unused",
            }
        )
    for remote_software in scan_data.get("remote_software", []):
        summary["issues"].append(
            {
                "description": f"Remote software detected: {remote_software}",
                "remediation": "Uninstall when not in active use",
            }
        )

    summary["dashboard"] = {
        "os_security": scan_data.get("os_security", {}),
        "user_security": scan_data.get("user_security", {}),
        "lock_security": scan_data.get("lock_security", {}),
        "drive_encryption": scan_data.get("drive_encryption", "Unknown"),
        "encryption_method": scan_data.get("encryption_method", "Unknown"),
        "windows_update": scan_data.get("windows_update", "Unknown"),
        "remote_desktop": scan_data.get("remote_desktop", "Unknown"),
        "guest_account": scan_data.get("guest_account", "Unknown"),
        "auto_login": scan_data.get("auto_login", "Unknown"),
        "windows_recovery": scan_data.get("windows_recovery", "Unknown"),
        "defender_realtime": scan_data.get("defender_realtime", "Unknown"),
        "defender_version": scan_data.get("defender_version", "Unknown"),
        "av_details": scan_data.get("av_details", []),
        "fw_details": scan_data.get("fw_details", {}),
        "browsers": scan_data.get("browsers", []),
        "password_managers": scan_data.get("password_managers", []),
        "remote_software": scan_data.get("remote_software", []),
        "storage": scan_data.get("storage", []),
    }

    summary["system_info"] = {
        "hardware_profile": scan_data.get("hardware_profile", {}),
        "processors": scan_data.get(
            "processors", scan_data.get("hardware_profile", {}).get("processors", [])
        ),
        "gpus": scan_data.get("gpus", []),
        "ram": scan_data.get("ram", "Unknown"),
        "system_manufacturer": scan_data.get("system_manufacturer", "Undetected"),
        "system_model": scan_data.get("system_model", "Undetected"),
        "device_type": scan_data.get("device_type", "Undetected"),
        "storage_devices": scan_data.get(
            "storage_devices", scan_data.get("hardware_profile", {}).get("storage_devices", [])
        ),
        "memory_module_count": scan_data.get("memory_module_count", "Undetected"),
        "memory_manufacturers": scan_data.get("memory_manufacturers", "Undetected"),
        "uptime": scan_data.get("uptime", "Undetected"),
        "uptime_seconds": scan_data.get("uptime_seconds", 0),
        "uptime_status": scan_data.get("uptime_status", "good"),
        "power_profile_name": scan_data.get("power_profile_name", "Undetected"),
        "power_profile_guid": scan_data.get("power_profile_guid", "Undetected"),
    }

    if programs_data:
        all_programs = programs_data.get("programs") or []
        export_all = bool(programs_data.get("pdf_export_all", False))
        display_limit = len(all_programs) if export_all else 30
        display_programs = all_programs[:display_limit]
        by_size = sorted(
            [program for program in all_programs if (program.get("size") or 0) > 0],
            key=lambda item: item.get("size", 0),
            reverse=True,
        )

        def _program_line(program):
            name = str(program.get("name", "Unknown"))
            size = (str(program.get("size")) + " MB") if program.get("size") else "-"
            return name + " (" + size + ")"

        summary["programs"] = {
            "program_count": programs_data.get("program_count", 0),
            "total_size": programs_data.get("total_program_size", "0 GB"),
            "size_breakdown": programs_data.get("size_breakdown", {}),
            "bad_software": programs_data.get("bad_software", []),
            "export_all": export_all,
            "export_order": programs_data.get("pdf_export_order", "current"),
            "display_count": len(display_programs),
            "display_programs": [_program_line(program) for program in display_programs],
            "top_programs": [_program_line(program) for program in all_programs[:30]],
            "top10_by_size": [
                {"name": program["name"], "size": program.get("size", 0)}
                for program in by_size[:10]
            ],
            "all_programs": [
                {"name": program["name"], "size": program.get("size", 0)}
                for program in all_programs
            ],
        }
    else:
        summary["programs"] = None

    if network_data:
        summary["network"] = {
            "internet_connected": network_data.get("internet_connected", False),
            "vpn_clients": network_data.get("vpn_clients", []),
            "dns_servers": network_data.get("dns_servers", []),
            "dns_alerts": network_data.get("dns_alerts", []),
            "dumping_software": network_data.get("dumping_software", []),
            "wifi_security": network_data.get("wifi_security", {}),
            "ssh_server_enabled": network_data.get("ssh_server_enabled", False),
            "telnet_enabled": network_data.get("telnet_enabled", False),
            "public_ip": network_data.get("public_ip", ""),
            "public_ipv6": network_data.get("public_ipv6", ""),
            "adapters": [
                {
                    "name": adapter.get("name", ""),
                    "ip": adapter.get("ip", ""),
                    "ipv6": adapter.get("ipv6", "None"),
                    "gateway": adapter.get("gateway", ""),
                    "type": adapter.get("type", ""),
                    "is_apipa": adapter.get("is_apipa", False),
                }
                for adapter in network_data.get("adapters", [])
            ],
        }
    else:
        summary["network"] = None

    return summary
