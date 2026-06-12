# main.py - application entry module
# Purpose: Initialize the native webview host, expose UI bridge functions, and coordinate app-level operations.

import threading
import sys
import os
import subprocess
import urllib.request
import urllib.error
import json
import hashlib

from core.system_utils import (
    get_ps,
    _version_tuple,
)
from core.browser_scan import (
    check_browser_version as check_browser_version_logic,
    open_browser_update as open_browser_update_logic,
)
from core.network_scan import (
    get_network_info_data,
    refresh_network_config,
    reset_network_adapter,
)
from core.scan_system import perform_scan_data
from core.program_scan import get_programs_data, launch_uninstaller
from core.summary_builder import build_summary
from core.version import (
    APP_USER_MODEL_ID,
    DETECTION_VERSION,
    ENGINE_VERSION,
    MAIN_PROGRAM_VERSION,
    VERSION,
    VERSION_SCHEME,
)
from core.webview_bridge import WebviewBridge


APP_WINDOW_TITLE = f"WebGeeks SystemShield v{VERSION}"
ui_bridge = WebviewBridge(window_title=APP_WINDOW_TITLE)

def resource_path(relative_path):
    """Resolve a path relative to the script/exe location, regardless of CWD."""
    try:

        base = sys._MEIPASS
    except AttributeError:

        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)

ui_bridge.init(resource_path('ui'))


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
        ui_bridge.update_scan_progress(msg, pct)
    except Exception:
        pass


def _version_metadata():
    """Return structured local version metadata for UI and update checks."""
    return {
        "version": VERSION,
        "version_scheme": VERSION_SCHEME,
        "main_program_version": MAIN_PROGRAM_VERSION,
        "engine_version": ENGINE_VERSION,
        "detection_version": DETECTION_VERSION,
    }

@ui_bridge.expose
def get_app_info():
    """Return local app metadata for the About page."""
    return {
        "name": "WebGeeks SystemShield",
        **_version_metadata(),
        "repo_url": "https://github.com/ImmaGundam/WebGeeks-SystemShield",
        "release_url": "https://github.com/ImmaGundam/WebGeeks-SystemShield/releases/latest",
        "website_url": "https://systemshield.net/"
    }


@ui_bridge.expose
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
            **_version_metadata(),
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
                **_version_metadata(),
                "current": VERSION,
                "latest": "Unknown",
                "release_url": "https://github.com/ImmaGundam/WebGeeks-SystemShield/releases",
                "message": "No published GitHub release was found."
            }
        return {
            "status": "error",
            **_version_metadata(),
            "current": VERSION,
            "latest": "Unknown",
            "message": f"GitHub returned HTTP {getattr(e, 'code', 'error')}"
        }
    except Exception as e:
        return {
            "status": "error",
            **_version_metadata(),
            "current": VERSION,
            "latest": "Unknown",
            "message": str(e)
        }

@ui_bridge.expose
def perform_scan():
    """Run the full SystemShield scan and return dashboard payload."""
    return perform_scan_data(_progress)

@ui_bridge.expose
def get_programs():
    """Return installed programs for Apps & Programs page."""
    return get_programs_data()


def check_browser_version(browser_name, version):
    """Check browser version status using core.browser_scan logic."""
    return check_browser_version_logic(browser_name, version)

# ==================== NETWORK SECURITY ====================

@ui_bridge.expose
def get_network_info():
    """Gather Network Security data using core.network_scan logic."""
    return get_network_info_data()
# ==================== VIRUSTOTAL ====================

@ui_bridge.expose
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


def vt_scan_file(filepath, api_key=""):
    """Upload a file to VirusTotal for scanning. Returns scan results or ID."""
    try:
        api_key = (api_key or "").strip()
        if not api_key:
            return {"error": "Enter your VirusTotal API key to use file scan."}
        if not os.path.exists(filepath):
            return {"error": "File not found"}

        sha256 = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
        result = vt_check_hash(sha256, api_key)
        if result and not result.get('error') and result.get("found") is not False:
            return result

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


@ui_bridge.expose
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

@ui_bridge.expose
def generate_summary(scan_data, programs_data=None, network_data=None):
    """Build a structured summary report from scan data with multi-page support."""
    return build_summary(scan_data, programs_data, network_data)


# ==================== SYSTEM OPERATIONS ====================

@ui_bridge.expose
def open_apps_settings():
    """Open Windows Apps & Features settings."""
    try:
        os.startfile("ms-settings:appsfeatures")
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@ui_bridge.expose
def open_windows_features():
    """Open 'Turn Windows features on or off' dialog."""
    try:
        subprocess.Popen(["optionalfeatures"], shell=True)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@ui_bridge.expose
def open_windows_update():
    """Open Windows Update settings."""
    try:
        os.startfile("ms-settings:windowsupdate")
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@ui_bridge.expose
def open_power_options():
    """Open classic Windows Power Options for power plan selection."""
    try:
        subprocess.Popen(["control.exe", "powercfg.cpl"])
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@ui_bridge.expose
def open_uac_settings():
    """Open UAC (User Account Control) settings dialog."""
    try:
        subprocess.Popen(["UserAccountControlSettings.exe"], shell=True)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@ui_bridge.expose
def open_netplwiz():
    """Open netplwiz (manage user accounts and auto-login)."""
    try:
        subprocess.Popen(["netplwiz"], shell=True)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@ui_bridge.expose
def open_computer_management():
    """Open Computer Management (manage local users and groups)."""
    try:
        subprocess.Popen(["compmgmt.msc"], shell=True)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@ui_bridge.expose
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


@ui_bridge.expose
def uninstall_program(program_name):
    """Run a program's registered uninstaller by display-name match."""
    return launch_uninstaller(program_name)


@ui_bridge.expose
def network_refresh():
    """Release and renew IP configuration on the default adapter."""
    return refresh_network_config()


@ui_bridge.expose
def network_reset():
    """Reset the main network adapter (disable then re-enable)."""
    return reset_network_adapter()


@ui_bridge.expose
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


@ui_bridge.expose
def open_browser_update(browser_name):
    """Launch a browser update/about page via core.browser_scan."""
    return open_browser_update_logic(browser_name)


# ==================== TITLEBAR THEMING (DWM) ====================
_DWMWA_DARK_MODE   = 20
_DWMWA_CAPTION_COL = 35
_WM_SETICON = 0x0080
_ICON_SMALL = 0
_ICON_BIG = 1
_IMAGE_ICON = 1
_LR_LOADFROMFILE = 0x0010
_LR_DEFAULTSIZE = 0x0040

_TB_COLOR_LIGHT = 0x004D2F21
_TB_COLOR_DARK  = 0x00181311
_APP_ICON_HANDLE = None


def _load_app_icon_handle():
    """Load the packaged application icon for native window branding."""
    global _APP_ICON_HANDLE
    if _APP_ICON_HANDLE is not None:
        return _APP_ICON_HANDLE
    try:
        import ctypes

        icon_path = resource_path(os.path.join("ui", "data", "icon.ico"))
        if not os.path.exists(icon_path):
            return None

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        handle = user32.LoadImageW(
            None,
            icon_path,
            _IMAGE_ICON,
            0,
            0,
            _LR_LOADFROMFILE | _LR_DEFAULTSIZE,
        )
        if handle:
            _APP_ICON_HANDLE = handle
        return _APP_ICON_HANDLE
    except Exception:
        return None


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
    """Set native window branding to match the SystemShield host.

    Light mode uses the sidebar blue. Dark mode uses the darker sidebar color.
    The title bar uses dark-caption mode in both themes so the title text and
    window controls remain readable against the dark branded colors.
    """
    try:
        import ctypes

        dwmapi = ctypes.WinDLL('dwmapi')
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        color = _TB_COLOR_DARK if use_dark else _TB_COLOR_LIGHT
        icon_handle = _load_app_icon_handle()

        for hwnd in _find_systemshield_windows():
            dark_val = ctypes.c_int(1)
            try:
                dwmapi.DwmSetWindowAttribute(hwnd, _DWMWA_DARK_MODE,
                                             ctypes.byref(dark_val), ctypes.sizeof(dark_val))
            except Exception:
                pass

            color_val = ctypes.c_int(color)
            try:
                dwmapi.DwmSetWindowAttribute(hwnd, _DWMWA_CAPTION_COL,
                                             ctypes.byref(color_val), ctypes.sizeof(color_val))
            except Exception:
                pass
            if icon_handle:
                try:
                    user32.SendMessageW(hwnd, _WM_SETICON, _ICON_SMALL, icon_handle)
                    user32.SendMessageW(hwnd, _WM_SETICON, _ICON_BIG, icon_handle)
                except Exception:
                    pass
    except Exception:
        pass


@ui_bridge.expose
def set_titlebar_theme(use_dark):
    """Called from JS theme toggle to keep the Windows title bar in sync."""
    _apply_titlebar_color(use_dark=bool(use_dark))


def _startup_titlebar():
    """Retry briefly while the native webview window is being created."""
    import time
    for _ in range(12):
        time.sleep(0.5)
        _apply_titlebar_color(use_dark=False)


threading.Thread(target=_startup_titlebar, daemon=True).start()
ui_bridge.set_api(ui_bridge.build_api())

ui_bridge.start(
    'index.html',
    size=(1460, 800),
)


