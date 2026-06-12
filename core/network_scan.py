# network_scan.py - network scan module
# Purpose: Collect network adapters, connectivity, DNS, VPN, and exposure signals.

import json
import socket
import subprocess
import time
import urllib.request

from core.detection_data import DUMPING_SOFTWARE, KNOWN_BAD_DNS, VPN_DETECTION
from core.system_utils import _match_registry_or_paths, get_ps, ps_first


def _json_list(raw):
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


def get_network_info_data():
    """Gather adapter, DNS, VPN, and exposure details for Network Security page."""
    result = {
        "adapters": [],
        "dns_servers": [],
        "dns_alerts": [],
        "vpn_clients": [],
        "internet_connected": False,
        "dumping_software": [],
    }

    try:
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=4)
            result["internet_connected"] = True
        except Exception:
            result["internet_connected"] = False

        dns_raw = ps_first(
            [
                "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses | ConvertTo-Json",
                "netsh interface ip show dns | Out-String",
            ]
        )
        adapters = []
        all_dns = []
        dns_data = _json_list(dns_raw)
        if dns_data:
            for entry in dns_data:
                alias = entry.get("InterfaceAlias", "Unknown")
                servers = entry.get("ServerAddresses", [])
                if isinstance(servers, str):
                    servers = [servers]
                adapters.append({"name": alias, "dns": servers})
                all_dns.extend(servers)
        elif dns_raw and dns_raw != "Not Detected":
            lines = dns_raw.split("\n")
            current_iface = ""
            current_dns = []
            for line in lines:
                line = line.strip()
                if "Configuration for interface" in line:
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
        result["dns_servers"] = list(set(all_dns))

        for ip in set(all_dns):
            if ip in KNOWN_BAD_DNS:
                result["dns_alerts"].append(f"Suspicious DNS server detected: {ip}")

        ip_raw = ps_first(
            [
                "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | Select-Object InterfaceAlias, IPAddress, PrefixLength | ConvertTo-Json",
                "ipconfig | Out-String",
            ]
        )
        for entry in _json_list(ip_raw):
            alias = entry.get("InterfaceAlias", "")
            for adapter in adapters:
                if adapter["name"] == alias:
                    adapter["ip"] = entry.get("IPAddress", "")
                    adapter["prefix"] = entry.get("PrefixLength", "")

        ipv6_raw = get_ps(
            "Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | Select-Object InterfaceAlias, IPAddress | ConvertTo-Json"
        )
        for entry in _json_list(ipv6_raw):
            alias = entry.get("InterfaceAlias", "")
            for adapter in adapters:
                if adapter["name"] == alias and "ipv6" not in adapter:
                    adapter["ipv6"] = entry.get("IPAddress", "")

        gw_raw = get_ps(
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object InterfaceAlias, NextHop | ConvertTo-Json"
        )
        for entry in _json_list(gw_raw):
            alias = entry.get("InterfaceAlias", "")
            for adapter in adapters:
                if adapter["name"] == alias:
                    adapter["gateway"] = entry.get("NextHop", "")

        adapter_details_raw = get_ps(
            "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MediaType | ConvertTo-Json"
        )
        for detail in _json_list(adapter_details_raw):
            adapter_name = detail.get("Name", "")
            desc = (detail.get("InterfaceDescription") or "").lower()
            status = detail.get("Status", "")
            for adapter in adapters:
                if adapter["name"] == adapter_name:
                    adapter["status"] = status
                    if any(keyword in desc for keyword in ["wi-fi", "wifi", "wireless", "802.11", "wlan"]):
                        adapter["type"] = "wifi"
                    elif any(
                        keyword in desc
                        for keyword in ["virtual", "vmware", "virtualbox", "hyper-v", "vethernet"]
                    ):
                        adapter["type"] = "virtual"
                    elif any(keyword in desc for keyword in ["loopback", "localhost"]):
                        adapter["type"] = "loopback"
                    elif any(keyword in adapter["name"].lower() for keyword in ["loopback", "localhost"]):
                        adapter["type"] = "loopback"
                    elif any(
                        keyword in adapter["name"].lower()
                        for keyword in ["vethernet", "vmware", "virtualbox", "virtual"]
                    ):
                        adapter["type"] = "virtual"
                    else:
                        adapter["type"] = "ethernet"
                    break

        for adapter in adapters:
            adapter.setdefault("ip", "")
            adapter.setdefault("prefix", "")
            adapter.setdefault("ipv6", "None")
            adapter.setdefault("gateway", "")
            adapter.setdefault("type", "ethernet")
            adapter.setdefault("status", "")
            ip_addr = adapter.get("ip", "")
            adapter["is_apipa"] = ip_addr.startswith("169.254.") if ip_addr else False

        type_order = {"wifi": 0, "ethernet": 1, "virtual": 2, "loopback": 3}
        adapters.sort(key=lambda item: type_order.get(item.get("type", "ethernet"), 1))
        result["adapters"] = adapters

        vpn_found = []
        for name, reg_paths, exe_paths in VPN_DETECTION:
            found, _evidence = _match_registry_or_paths(reg_paths, exe_paths)
            if found:
                vpn_found.append(name)
        result["vpn_clients"] = vpn_found

        result["vpn_active"] = False
        result["vpn_protocol"] = ""
        result["vpn_adapter_name"] = ""
        try:
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
            vpn_adapters = _json_list(vpn_adapter_raw)
            if vpn_adapters:
                result["vpn_active"] = True
                result["vpn_adapter_name"] = vpn_adapters[0].get("Name", "")
                desc = (vpn_adapters[0].get("InterfaceDescription") or "").lower()
                if "wireguard" in desc or "wintun" in desc:
                    result["vpn_protocol"] = "WireGuard"
                elif "tap" in desc:
                    result["vpn_protocol"] = "OpenVPN (TAP)"
                elif "tun" in desc:
                    result["vpn_protocol"] = "OpenVPN (TUN)"
                else:
                    result["vpn_protocol"] = "Unknown"

            if not result["vpn_active"]:
                ras_raw = get_ps(
                    "Get-VpnConnection | Where-Object {$_.ConnectionStatus -eq 'Connected'} | "
                    "Select-Object Name, TunnelType | ConvertTo-Json"
                )
                ras_connections = _json_list(ras_raw)
                if ras_connections:
                    result["vpn_active"] = True
                    result["vpn_adapter_name"] = ras_connections[0].get("Name", "")
                    result["vpn_protocol"] = ras_connections[0].get("TunnelType", "Unknown")
        except Exception:
            pass

        dump_found = []
        for name, reg_paths, exe_paths in DUMPING_SOFTWARE:
            found, _evidence = _match_registry_or_paths(reg_paths, exe_paths)
            if found:
                dump_found.append(name)
        result["dumping_software"] = dump_found

        try:
            wifi_raw = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                timeout=10,
                stderr=subprocess.STDOUT,
                shell=True,
            ).decode(errors="ignore").strip()
            wifi_info = {}
            for line in wifi_raw.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, _, value = line.partition(":")
                    wifi_info[key.strip().lower()] = value.strip()
            ssid = wifi_info.get("ssid", "")
            auth = wifi_info.get("authentication", "")
            cipher = wifi_info.get("cipher", "")
            signal = wifi_info.get("signal", "")
            radio = wifi_info.get("radio type", "")
            channel = wifi_info.get("channel", "")
            rx_rate = wifi_info.get("receive rate (mbps)", "")
            tx_rate = wifi_info.get("transmit rate (mbps)", "")
            if ssid:
                result["wifi_security"] = {
                    "status": "Connected",
                    "ssid": ssid,
                    "authentication": auth,
                    "cipher": cipher,
                    "secured": auth.lower() not in ("open", ""),
                    "wps_enabled": None,
                    "signal": signal,
                    "radio_type": radio,
                    "channel": channel,
                    "rx_rate": rx_rate,
                    "tx_rate": tx_rate,
                }
            else:
                result["wifi_security"] = {"status": "Not connected to WiFi"}
        except Exception:
            result["wifi_security"] = {"status": "Not connected to WiFi"}

        try:
            ssh_svc_status = get_ps(
                "Get-Service sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"
            )
            ssh_svc_start = get_ps(
                "Get-Service sshd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty StartType"
            )
            if not ssh_svc_status or ssh_svc_status in ("Not Detected", ""):
                result["ssh_server_status"] = "Not Installed"
            else:
                result["ssh_server_status"] = ssh_svc_status
            result["ssh_server_start_type"] = (
                ssh_svc_start if ssh_svc_start not in ("Not Detected", "", None) else "Unknown"
            )
            result["ssh_server_enabled"] = ssh_svc_status == "Running"
        except Exception:
            result["ssh_server_status"] = "Unknown"
            result["ssh_server_start_type"] = "Unknown"
            result["ssh_server_enabled"] = False

        try:
            telnet_state = get_ps(
                "(Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue).State"
            )
            result["telnet_enabled"] = "Enabled" in (telnet_state or "")
        except Exception:
            result["telnet_enabled"] = False

        result["public_ip"] = ""
        result["public_ipv6"] = ""
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as response:
                result["public_ip"] = response.read().decode().strip()
        except Exception:
            pass
        try:
            with urllib.request.urlopen("https://api64.ipify.org", timeout=5) as response:
                ipv6 = response.read().decode().strip()
                if ":" in ipv6:
                    result["public_ipv6"] = ipv6
        except Exception:
            pass

        profile_raw = get_ps(
            "Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory | ConvertTo-Json"
        )
        for profile in _json_list(profile_raw):
            alias = profile.get("InterfaceAlias", "")
            category = profile.get("NetworkCategory", "")
            if isinstance(category, int):
                category = {0: "Public", 1: "Private", 2: "Domain"}.get(category, str(category))
            for adapter in adapters:
                if adapter["name"] == alias:
                    adapter["network_profile"] = str(category)
        for adapter in adapters:
            adapter.setdefault("network_profile", "")

    except Exception as exc:
        result["error"] = str(exc)

    return result


def refresh_network_config():
    """Release and renew IP configuration on the default adapter."""
    try:
        subprocess.run(["ipconfig", "/release"], shell=True, timeout=15, capture_output=True)
        subprocess.run(["ipconfig", "/renew"], shell=True, timeout=30, capture_output=True)
        return {"status": "ok"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def reset_network_adapter():
    """Reset the primary active network adapter (disable then re-enable)."""
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
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
