# program_scan.py - program scan module
# Purpose: Enumerate installed programs, classify software, and launch uninstall flows.

import json
import os
import subprocess

from core.detection_data import (
    BAD_SOFTWARE,
    CREDENTIAL_STEALERS,
    CRYPTO_MINERS,
    DATA_EXFIL_TOOLS,
    HACKING_UTILS,
    RAT_TOOLS,
    REMOTE_SHELL_TOOLS,
    SCAMWARE,
    SYSTEM_PUBLISHERS,
    TORRENT_CLIENTS,
)
from core.system_utils import enumerate_uninstall_entries, get_ps


def _is_system_program(entry):
    """Determine if a program is a Windows/system component."""
    publisher = (entry.get("Publisher") or "").lower()
    name = (entry.get("DisplayName") or "").lower()
    system_component = entry.get("SystemComponent")
    if system_component and str(system_component) == "1":
        return True
    for system_publisher in SYSTEM_PUBLISHERS:
        if system_publisher in publisher:
            return True
    if any(
        keyword in name
        for keyword in [
            "driver",
            "runtime",
            ".net framework",
            "visual c++",
            "redistributable",
            "windows sdk",
            "windows kit",
        ]
    ):
        return True
    return False


def _name_hits(program_list, keyword_list):
    """Return program names that match any keyword in keyword_list."""
    hits = []
    for program in program_list:
        for keyword in keyword_list:
            if keyword.lower() in program["name"].lower():
                hits.append(program["name"])
                break
    return hits


def get_programs_data():
    """Return installed programs with classification, totals, and threat matches."""
    try:
        programs = []
        total_mb = 0.0
        system_mb = 0.0
        user_mb = 0.0
        store_mb = 0.0
        seen = set()

        for entry in enumerate_uninstall_entries():
            name = (entry.get("DisplayName") or "").strip()
            if not name or name in seen:
                continue

            seen.add(name)
            try:
                size_mb = round(float(entry.get("EstimatedSize", 0)) / 1024.0, 2)
            except Exception:
                size_mb = 0.0

            publisher = entry.get("Publisher", "") or ""
            uninstall_str = entry.get("UninstallString", "") or ""
            is_system = _is_system_program(entry)
            source = "Windows" if is_system else "User"
            version_str = (entry.get("DisplayVersion") or "").strip()

            programs.append(
                {
                    "name": name,
                    "size": size_mb,
                    "publisher": publisher,
                    "source": source,
                    "uninstall": uninstall_str,
                    "version": version_str,
                }
            )

            total_mb += size_mb
            if is_system:
                system_mb += size_mb
            else:
                user_mb += size_mb

        try:
            store_apps_raw = get_ps(
                "Get-AppxPackage | Where-Object {$_.IsFramework -eq $false -and $_.SignatureKind -eq 'Store'} | "
                "Select-Object Name, Publisher, InstallLocation | ConvertTo-Json"
            )
            if store_apps_raw and store_apps_raw != "Not Detected":
                apps = json.loads(store_apps_raw)
                if isinstance(apps, dict):
                    apps = [apps]
                for app in apps:
                    app_name = app.get("Name", "")
                    if not app_name:
                        continue
                    display_name = app_name.split(".")[-1] if "." in app_name else app_name
                    if display_name in seen:
                        continue

                    seen.add(display_name)
                    app_mb = 0.0
                    install_location = app.get("InstallLocation", "")
                    if install_location and os.path.isdir(install_location):
                        try:
                            total_bytes = sum(
                                os.path.getsize(os.path.join(directory_path, file_name))
                                for directory_path, _dir_names, file_names in os.walk(install_location)
                                for file_name in file_names
                            )
                            app_mb = round(total_bytes / (1024 * 1024), 2)
                        except Exception:
                            pass

                    programs.append(
                        {
                            "name": display_name,
                            "size": app_mb,
                            "publisher": app.get("Publisher", "Microsoft Store"),
                            "source": "Store",
                            "uninstall": "",
                        }
                    )
                    store_mb += app_mb
                    total_mb += app_mb
        except Exception:
            pass

        programs.sort(key=lambda item: item["name"].lower())

        threat_lists = [
            ("bad_software", BAD_SOFTWARE),
            ("scamware", SCAMWARE),
            ("torrent_clients", TORRENT_CLIENTS),
            ("crypto_miners", CRYPTO_MINERS),
            ("hacking_utils", HACKING_UTILS),
            ("data_exfil_tools", DATA_EXFIL_TOOLS),
            ("remote_shell_tools", REMOTE_SHELL_TOOLS),
            ("rat_tools", RAT_TOOLS),
            ("credential_stealers", CREDENTIAL_STEALERS),
        ]
        threat_results = {key: _name_hits(programs, values) for key, values in threat_lists}
        bad_hits = threat_results["bad_software"]

        winrar_safe_version = (7, 13)
        for program in programs:
            if "winrar" in program["name"].lower():
                version_str = program.get("version", "")
                try:
                    parts = tuple(int(x) for x in version_str.split(".") if x.isdigit())[:2]
                    if parts and parts < winrar_safe_version:
                        bad_hits.append(program["name"])
                except Exception:
                    bad_hits.append(program["name"])

        return {
            "programs": programs,
            "total_program_size": f"{round(total_mb / 1024.0, 2)} GB",
            "program_count": len(programs),
            "bad_software": bad_hits,
            "scamware": threat_results["scamware"],
            "torrent_clients": threat_results["torrent_clients"],
            "crypto_miners": threat_results["crypto_miners"],
            "hacking_utils": threat_results["hacking_utils"],
            "data_exfil_tools": threat_results["data_exfil_tools"],
            "remote_shell_tools": threat_results["remote_shell_tools"],
            "rat_tools": threat_results["rat_tools"],
            "credential_stealers": threat_results["credential_stealers"],
            "size_breakdown": {
                "system_size": f"{round(system_mb / 1024.0, 2)} GB",
                "user_size": f"{round(user_mb / 1024.0, 2)} GB",
                "store_size": f"{round(store_mb / 1024.0, 2)} GB",
                "system_mb": round(system_mb, 2),
                "user_mb": round(user_mb, 2),
                "store_mb": round(store_mb, 2),
            },
        }
    except Exception:
        return {
            "programs": [],
            "total_program_size": "0 GB",
            "program_count": 0,
            "bad_software": [],
            "size_breakdown": {
                "system_size": "0 GB",
                "user_size": "0 GB",
                "store_size": "0 GB",
                "system_mb": 0,
                "user_mb": 0,
                "store_mb": 0,
            },
        }


def launch_uninstaller(program_name):
    """Run a program's registered uninstaller by display-name match."""
    try:
        target = (program_name or "").strip()
        if not target:
            return {"status": "error", "message": "No program name was provided."}

        for entry in enumerate_uninstall_entries():
            display_name = (entry.get("DisplayName") or "").strip()
            if not display_name:
                continue
            if target.lower() not in display_name.lower():
                continue

            uninstall_str = (entry.get("UninstallString") or "").strip()
            if uninstall_str:
                subprocess.Popen(uninstall_str, shell=True)
                return {"status": "ok", "message": f"Uninstaller opened for {display_name}."}
            return {"status": "error", "message": f"No registered uninstaller was found for {display_name}."}

        return {"status": "error", "message": f"No registered uninstaller was found for {target}."}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
