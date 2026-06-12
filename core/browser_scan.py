# browser_scan.py - browser scan module
# Purpose: Detect installed browsers, compare versions, and open browser update surfaces.

import os
import subprocess
import winreg

from core.detection_data import (
    BROWSER_EXE_PATHS,
    BROWSER_META,
    BROWSER_REGISTRY,
)
from core.browser_versions import (
    get_browser_version_state,
    get_latest_browser_versions,
)
from core.system_utils import get_exe_version, get_ps


def _firefox_app_version(exe_path):
    ini_path = os.path.join(os.path.dirname(exe_path), "application.ini")
    try:
        with open(ini_path, "r", encoding="utf-8", errors="replace") as handle:
            in_app_section = False
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    in_app_section = line.lower() == "[app]"
                    continue
                if in_app_section and line.lower().startswith("version="):
                    version = line.split("=", 1)[1].strip()
                    if version:
                        return version
    except Exception:
        return ""
    return ""


def fetch_latest_browser_versions(force=False):
    """Fetch latest browser-track major versions with caching."""
    return get_latest_browser_versions(force=force)


def get_latest_versions():
    """Return latest browser-track major versions from the cached live provider."""
    return fetch_latest_browser_versions(force=False)


def detect_installed_browsers():
    """Detect installed browsers using registry and executable probes."""
    browsers = []
    found_browsers = set()

    for name, path, value_name, hive in BROWSER_REGISTRY:
        if name in found_browsers:
            continue
        try:
            with winreg.OpenKey(hive, path) as key:
                version, _ = winreg.QueryValueEx(key, value_name)
                if version:
                    meta = BROWSER_META.get(name, {"engine": "Unknown", "discontinued": False})
                    browsers.append(
                        {
                            "name": name,
                            "version": str(version),
                            "engine": meta["engine"],
                            "discontinued": meta["discontinued"],
                        }
                    )
                    found_browsers.add(name)
        except Exception:
            continue

    for name, paths in BROWSER_EXE_PATHS:
        if name in found_browsers:
            continue
        for exe_path in paths:
            if os.path.exists(exe_path):
                try:
                    version = _firefox_app_version(exe_path) if BROWSER_META.get(name, {}).get("engine") == "Gecko" else ""
                    if not version:
                        version = get_exe_version(exe_path)
                    if not version:
                        version = get_ps(f"(Get-Item '{exe_path}').VersionInfo.ProductVersion")
                    if version and version != "Not Detected":
                        meta = BROWSER_META.get(name, {"engine": "Unknown", "discontinued": False})
                        browsers.append(
                            {
                                "name": name,
                                "version": version,
                                "engine": meta["engine"],
                                "discontinued": meta["discontinued"],
                            }
                        )
                        found_browsers.add(name)
                        break
                except Exception:
                    meta = BROWSER_META.get(name, {"engine": "Unknown", "discontinued": False})
                    browsers.append(
                        {
                            "name": name,
                            "version": "Installed",
                            "engine": meta["engine"],
                            "discontinued": meta["discontinued"],
                        }
                    )
                    found_browsers.add(name)
                    break

    return browsers


def check_browser_version(browser_name, version):
    """Return browser status label: good, caution, or risk."""
    try:
        if not version or version in ["Detected", "Installed", "Not Detected"]:
            return "caution"
        major = int(str(version).split(".")[0])
        latest = get_latest_versions().get(browser_name)
        if isinstance(latest, int):
            state = get_browser_version_state(browser_name) or {}
            source_type = state.get("source_type", "")
            if (
                browser_name in {"Brave", "Opera", "Opera GX", "Vivaldi", "Arc"}
                and source_type == "derived_upstream"
                and major < latest
            ):
                return "caution"
            if major >= latest:
                return "good"
            if major >= latest - 2:
                return "caution"
            return "risk"
        return "caution"
    except Exception:
        return "caution"


def open_browser_update(browser_name):
    """Open the selected browser's native update/help page when possible."""
    internal_urls = {
        "Google Chrome": "chrome://settings/help",
        "Microsoft Edge": "edge://settings/help",
        "Brave": "brave://settings/help",
        "Opera": "opera://update",
        "Opera GX": "opera://update",
        "Vivaldi": "vivaldi://about",
        "Yandex Browser": "browser://settings/help",
        "Avast Secure Browser": "avast://settings/help",
        "AVG Secure Browser": "avg://settings/help",
        "Naver Whale": "whale://settings/help",
        "Chromium": "chrome://settings/help",
        "CentBrowser": "chrome://settings/help",
        "SRWare Iron": "chrome://settings/help",
        "Slimjet": "chrome://settings/help",
        "Comodo Dragon": "chrome://settings/help",
        "Torch": "chrome://settings/help",
        "CoolNovo": "chrome://settings/help",
        "Iridium": "chrome://settings/help",
        "Epic Privacy Browser": "chrome://settings/help",
        "360 Browser": "chrome://settings/help",
        "Coc Coc": "chrome://settings/help",
        "Mozilla Firefox": "about:preferences",
        "Firefox Developer Edition": "about:preferences",
        "Waterfox": "about:preferences",
        "LibreWolf": "about:preferences",
        "Zen Browser": "about:preferences",
        "Tor Browser": "about:preferences",
        "Pale Moon": "about:preferences",
        "SeaMonkey": "about:preferences",
        "K-Meleon": "about:preferences",
        "Basilisk": "about:preferences",
        "IceCat": "about:preferences",
    }

    exe_map = {
        "Google Chrome": [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ],
        "Microsoft Edge": [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ],
        "Mozilla Firefox": [
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
        ],
        "Brave": [r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"],
        "Opera": [
            r"C:\Program Files\Opera\launcher.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera\launcher.exe"),
        ],
        "Opera GX": [os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera GX\launcher.exe")],
        "Vivaldi": [
            r"C:\Program Files\Vivaldi\Application\vivaldi.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Vivaldi\Application\vivaldi.exe"),
        ],
        "Waterfox": [r"C:\Program Files\Waterfox\waterfox.exe"],
        "LibreWolf": [r"C:\Program Files\LibreWolf\librewolf.exe"],
        "Tor Browser": [os.path.expandvars(r"%USERPROFILE%\Desktop\Tor Browser\Browser\firefox.exe")],
        "Chromium": [os.path.expandvars(r"%LOCALAPPDATA%\Chromium\Application\chrome.exe")],
        "Pale Moon": [r"C:\Program Files\Pale Moon\palemoon.exe"],
        "Slimjet": [r"C:\Program Files\Slimjet\slimjet.exe"],
        "Comodo Dragon": [r"C:\Program Files\Comodo\Dragon\dragon.exe"],
        "SeaMonkey": [r"C:\Program Files\SeaMonkey\seamonkey.exe"],
        "SRWare Iron": [
            r"C:\Program Files\SRWare Iron\iron.exe",
            r"C:\Program Files (x86)\SRWare Iron\iron.exe",
        ],
        "Yandex Browser": [os.path.expandvars(r"%LOCALAPPDATA%\Yandex\YandexBrowser\Application\browser.exe")],
        "Avast Secure Browser": [r"C:\Program Files\AVAST Software\Browser\Application\AvastBrowser.exe"],
        "AVG Secure Browser": [r"C:\Program Files\AVG\Browser\Application\AVGBrowser.exe"],
        "Torch": [os.path.expandvars(r"%LOCALAPPDATA%\Torch\Application\torch.exe")],
        "Naver Whale": [r"C:\Program Files\Naver\Naver Whale\Application\whale.exe"],
        "Iridium": [r"C:\Program Files\Iridium\iridium.exe"],
        "Epic Privacy Browser": [
            r"C:\Program Files\Epic Privacy Browser\Application\epic.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Epic Privacy Browser\Application\epic.exe"),
        ],
        "CentBrowser": [os.path.expandvars(r"%LOCALAPPDATA%\CentBrowser\Application\chrome.exe")],
        "360 Browser": [r"C:\Program Files\360\360Browser\360Chrome.exe"],
        "Coc Coc": [os.path.expandvars(r"%LOCALAPPDATA%\CocCoc\Browser\Application\browser.exe")],
        "Firefox Developer Edition": [r"C:\Program Files\Firefox Developer Edition\firefox.exe"],
        "Zen Browser": [r"C:\Program Files\Zen Browser\zen.exe"],
        "Maxthon": [r"C:\Program Files\Maxthon\Bin\Maxthon.exe"],
        "K-Meleon": [r"C:\Program Files\K-Meleon\k-meleon.exe"],
        "Basilisk": [r"C:\Program Files\Basilisk\basilisk.exe"],
        "IceCat": [r"C:\Program Files\GNU IceCat\icecat.exe"],
        "CoolNovo": [r"C:\Program Files\CoolNovo\coolnovo.exe"],
    }

    exe = None
    for path in exe_map.get(browser_name, []):
        if os.path.exists(path):
            exe = path
            break

    internal_url = internal_urls.get(browser_name)
    if exe and internal_url:
        try:
            subprocess.Popen([exe, internal_url])
            return {"status": "ok", "message": f"Opening {browser_name} settings"}
        except Exception:
            pass

    fallback_urls = {
        "Google Chrome": "https://support.google.com/chrome/answer/95414",
        "Mozilla Firefox": "https://support.mozilla.org/en-US/kb/update-firefox-latest-release",
        "Opera": "https://www.opera.com/download",
        "Opera GX": "https://www.opera.com/gx",
        "Vivaldi": "https://vivaldi.com/download/",
        "Maxthon": "https://www.maxthon.com/",
    }
    fallback_url = fallback_urls.get(browser_name)
    if fallback_url:
        try:
            os.startfile(fallback_url)
            return {"status": "ok", "message": f"Opening download page for {browser_name}"}
        except Exception:
            pass

    return {"status": "error", "message": f"Could not open update page for {browser_name}"}
