"""
detection_lists.py  -  WebGeeks SystemShield Detection List v1.3.2
Reference data for all detection and classification logic in System_Scanner.py.

Each threat category lives in its own clearly-named constant.
Edit this file to add/remove entries without ever touching scan logic.

NAME-BASED LISTS  (substring match against installed program display names)
    BAD_SOFTWARE        - PUPs / bloatware
    SCAMWARE            - fake optimizers / scam repair tools
    TORRENT_CLIENTS     - bad torrent / P2P software
    CRYPTO_MINERS       - cryptocurrency mining software
    HACKING_UTILS       - pentest / offensive-security tools
    DATA_EXFIL_TOOLS    - bulk-transfer / sync tools abused in ransomware
    REMOTE_SHELL_TOOLS  - SSH / shell / lateral-movement utilities
    RAT_TOOLS           - Remote Access Trojans / malware frameworks
    CREDENTIAL_STEALERS - info-stealer / credential-dumping malware

REGISTRY + EXE-PATH LISTS  (name, [reg_keys], [exe_paths])
    VPN_DETECTION       - VPN clients
    PM_DETECTION        - password managers
    RS_DETECTION        - remote access / remote control software
    RMM_DETECTION       - Remote Monitoring & Management platforms

BROWSER DATA
    LATEST_BROWSER_VERSIONS, BROWSER_META, BROWSER_REGISTRY, BROWSER_EXE_PATHS

NETWORK DATA
    KNOWN_BAD_DNS

PROGRAM CLASSIFICATION
    SYSTEM_PUBLISHERS
"""

import os
import winreg as _winreg

# Detection list version. Keep this matched with System_Scanner.VERSION and About page.
DETECTION_LIST_VERSION = "1.3.2"


# ============================================================================
# NAME-BASED DETECTION LISTS
# Used in get_programs() -- substring match (case-insensitive) against the
# DisplayName of every installed program.
# ============================================================================

# -- Potentially Unwanted Programs / Bloatware --------------------------------
BAD_SOFTWARE = [
    'McAfee', 'Norton', 'Avast', 'AVG', 'CCleaner', 'IObit',
    'Advanced SystemCare', 'Driver Booster', 'uTorrent', 'Clean Master',
    'PC Optimizer Pro', 'MyCleanPC', 'WinZip',
    'Ask Toolbar', 'Conduit', 'Babylon', 'Toolbar',
]

# NOTE: WinRAR is intentionally excluded from BAD_SOFTWARE. It is handled
# by a version-aware check in get_programs() that only flags versions < 7.13
# (vulnerable to CVE-2025-8088 / CVE-2025-6218). 7.13+ is considered safe.

# -- Scamware / Fake System Optimizers ----------------------------------------
SCAMWARE = [
    'SpeedUpMyPC',
    'PC Speed Maximizer',
    'SlimCleaner',
    'Registry Reviver',
    'TotalAV',
    'Restoro',
    'Driver Easy',
]

# -- Torrent / P2P Clients ----------------------------------------------------
TORRENT_CLIENTS = [
    'uTorrent',
    'BitTorrent',
    'qBittorrent',
    'Deluge',
    'Transmission',
    'Tixati',
    'BitComet',
    'Vuze',
    'FrostWire',
    'Tribler',
]

# -- Cryptocurrency Miners ----------------------------------------------------
# Presence on an endpoint is almost always malicious or policy-violating.
CRYPTO_MINERS = [
    'XMRig',
    'XMR-Stak',
    'Claymore Miner',
    'PhoenixMiner',
    'T-Rex Miner',
    'GMiner',
    'LolMiner',
    'TeamRedMiner',
    'Bminer',
    'NiceHash',
    'SRBMiner',
    'Nanominer',
    'WildRig',
    'MultiMiner',
]

# -- Hacking / Pentest Utilities ----------------------------------------------
# Legitimate in controlled lab environments; flagged as high-risk on endpoints.
HACKING_UTILS = [
    'Metasploit',
    'Nmap',
    'Wireshark',
    'Burp Suite',
    'SQLmap',
    'John the Ripper',
    'Hashcat',
    'Hydra',
    'Aircrack-ng',
    'Ettercap',
    'Cain & Abel',
    'Mimikatz',
]

# -- Data Exfiltration / Bulk-Transfer Tools ----------------------------------
# Legitimate sync tools frequently abused by ransomware operators.
DATA_EXFIL_TOOLS = [
    'MegaSync',
    'Resilio Sync',
    'Syncthing',
    'FileZilla',
    'WinSCP',
    'Rclone',
    'ExMatter',
    'rsync',
    'Cyberduck',
    'Air Explorer',
]

# -- Remote Shell / Lateral-Movement Tools ------------------------------------
# Third-party tools only — flagged for awareness rather than automatic risk.
# NOTE: OpenSSH and Telnet are built-in Windows optional features and are
# intentionally excluded here. Their service/feature state is checked
# separately in get_network_info() via ssh_server_status / telnet_enabled,
# which correctly distinguishes Disabled from Running.
REMOTE_SHELL_TOOLS = [
    'PuTTY',
    'MobaXterm',
    'SecureCRT',
    'KiTTY',
    'Netcat',
    'Ncat',
    'PsExec',
]

# -- RAT / Malware Frameworks -------------------------------------------------
# Critical -- should never appear on a clean machine.
RAT_TOOLS = [
    'DarkComet',
    'njRAT',
    'NanoCore',
    'Quasar RAT',
    'AsyncRAT',
    'Remcos',
    'NetSupport RAT',
    'PlugX',
    'Poison Ivy',
    'Orcus RAT',
    'LuminosityLink',
    'Revenge RAT',
    'BlackShades',
    'Havij',
]

# -- Credential / Info Stealers -----------------------------------------------
# Critical -- should never appear on a clean machine.
CREDENTIAL_STEALERS = [
    'RedLine',
    'Vidar',
    'Raccoon Stealer',
    'AZORult',
    'LokiBot',
]


# ============================================================================
# REGISTRY + EXE-PATH DETECTION LISTS
# Format per entry: (display_name, [registry_keys], [exe_paths])
#   registry_keys starting with "SOFTWARE\" -> HKLM; "Software\" -> HKCU
#   Wildcard (*) in exe_paths is resolved with glob.glob()
# ============================================================================

# -- VPN Clients --------------------------------------------------------------
VPN_DETECTION = [
    ("NordVPN",
        [r"SOFTWARE\NordVPN"],
        [r"C:\Program Files\NordVPN\NordVPN.exe"]),
    ("ExpressVPN",
        [r"SOFTWARE\ExpressVPN"],
        [r"C:\Program Files (x86)\ExpressVPN\expressvpn-ui\ExpressVPN.exe"]),
    ("Surfshark",
        [r"SOFTWARE\Surfshark"],
        [r"C:\Program Files\Surfshark\Surfshark.exe"]),
    ("CyberGhost",
        [r"SOFTWARE\CyberGhost"],
        [r"C:\Program Files\CyberGhost 8\CyberGhost.exe"]),
    ("Private Internet Access",
        [r"SOFTWARE\Private Internet Access"],
        [r"C:\Program Files\Private Internet Access\pia-client.exe"]),
    ("ProtonVPN",
        [r"SOFTWARE\Proton\VPN"],
        [r"C:\Program Files\Proton\VPN\ProtonVPN.exe"]),
    ("Windscribe",
        [r"SOFTWARE\Windscribe"],
        [r"C:\Program Files\Windscribe\Windscribe.exe"]),
    ("Mullvad VPN",
        [r"SOFTWARE\Mullvad VPN"],
        [r"C:\Program Files\Mullvad VPN\mullvad-vpn.exe"]),
    ("TunnelBear",
        [r"SOFTWARE\TunnelBear"],
        [r"C:\Program Files (x86)\TunnelBear\TunnelBear.exe"]),
    ("Hotspot Shield",
        [r"SOFTWARE\Hotspot Shield", r"SOFTWARE\AnchorFree\Hotspot Shield"],
        [r"C:\Program Files\Hotspot Shield\bin\hsscp.exe"]),
    ("IPVanish",
        [r"SOFTWARE\IPVanish"],
        [r"C:\Program Files\IPVanish\IPVanish.exe"]),
    ("WireGuard",
        [r"SOFTWARE\WireGuard"],
        [r"C:\Program Files\WireGuard\wireguard.exe"]),
    ("OpenVPN",
        [r"SOFTWARE\OpenVPN"],
        [r"C:\Program Files\OpenVPN\bin\openvpn-gui.exe"]),
    ("Cisco AnyConnect",
        [r"SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client"],
        [r"C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"]),
    ("GlobalProtect",
        [r"SOFTWARE\Palo Alto Networks\GlobalProtect"],
        [r"C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe"]),
    ("FortiClient",
        [r"SOFTWARE\Fortinet\FortiClient"],
        [r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe"]),
    ("Pulse Secure",
        [r"SOFTWARE\Pulse Secure"],
        [r"C:\Program Files (x86)\Pulse Secure\Pulse\PulseSecure.exe"]),
    ("SoftEther VPN",
        [],
        [r"C:\Program Files\SoftEther VPN Client\vpnclient.exe"]),
    ("HideMyAss",
        [r"SOFTWARE\HMA! Pro VPN"],
        []),
    ("TorGuard",
        [],
        [r"C:\Program Files\TorGuard\TorGuard.exe"]),
    ("IVPN",
        [],
        [r"C:\Program Files\IVPN Client\IVPN.exe"]),
    ("AirVPN",
        [],
        [r"C:\Program Files\AirVPN\Eddie-UI.exe"]),
    ("StrongVPN",
        [r"SOFTWARE\StrongVPN"],
        []),
    ("VyprVPN",
        [r"SOFTWARE\Golden Frog\VyprVPN"],
        [r"C:\Program Files\VyprVPN\VyprVPN.exe"]),
    ("Kaspersky VPN",
        [r"SOFTWARE\KasperskyLab\KSDE"],
        [r"C:\Program Files (x86)\Kaspersky Lab\Kaspersky VPN Secure Connection*\ksde.exe"]),
]

# -- Password Managers --------------------------------------------------------
PM_DETECTION = [
    ("1Password",
        [r"Software\AgileBits\1Password", r"SOFTWARE\AgileBits\1Password"],
        [r"C:\Program Files\1Password\app\1Password.exe",
         r"C:\Users\*\AppData\Local\1Password\app\*\1Password.exe"]),
    ("LastPass",
        [r"Software\LastPass", r"SOFTWARE\LastPass"],
        [r"C:\Program Files (x86)\LastPass\lastpass.exe"]),
    ("Dashlane",
        [r"Software\Dashlane\Dashlane"],
        [r"C:\Program Files\Dashlane\Dashlane.exe"]),
    ("Bitwarden",
        [r"Software\Bitwarden"],
        [r"C:\Program Files\Bitwarden\Bitwarden.exe",
         r"C:\Users\*\AppData\Local\Programs\Bitwarden\Bitwarden.exe"]),
    ("Keeper",
        [r"Software\Keeper Security"],
        [r"C:\Program Files (x86)\Keeper\keeper.exe"]),
    ("NordPass",
        [r"Software\NordPass"],
        [r"C:\Program Files\NordPass\NordPass.exe",
         r"C:\Users\*\AppData\Local\Programs\nordpass\NordPass.exe"]),
    ("RoboForm",
        [r"Software\Siber Systems\RoboForm"],
        [r"C:\Program Files (x86)\Siber Systems\AI RoboForm\RoboForm.exe"]),
    ("Enpass",
        [r"Software\Enpass"],
        [r"C:\Program Files\Enpass\Enpass.exe"]),
    ("Sticky Password",
        [r"Software\Sticky Password"],
        [r"C:\Program Files\Sticky Password\stpass.exe"]),
    ("KeePass",
        [],
        [r"C:\Program Files\KeePass Password Safe 2\KeePass.exe",
         r"C:\Program Files (x86)\KeePass Password Safe 2\KeePass.exe"]),
    ("Proton Pass",
        [r"Software\Proton\Proton Pass"],
        []),
    ("True Key",
        [r"Software\Intel Security\True Key", r"SOFTWARE\TrueKey"],
        [r"C:\Program Files\Intel Security\True Key\TrueKey.exe"]),
    ("Password Safe",
        [],
        [r"C:\Program Files\Password Safe\pwsafe.exe",
         r"C:\Program Files (x86)\Password Safe\pwsafe.exe"]),
    ("Zoho Vault",
        [r"Software\Zoho\Vault"],
        []),
    ("mSecure",
        [r"Software\mSeven Software\mSecure"],
        []),
    ("SafeInCloud",
        [r"Software\SafeInCloud"],
        []),
]

# -- Remote Access / Remote Control Software ----------------------------------
RS_DETECTION = [
    ("TeamViewer",
        [r"SOFTWARE\TeamViewer", r"Software\TeamViewer"],
        [r"C:\Program Files\TeamViewer\TeamViewer.exe",
         r"C:\Program Files (x86)\TeamViewer\TeamViewer.exe"]),
    ("AnyDesk",
        [r"SOFTWARE\AnyDesk", r"Software\AnyDesk"],
        [r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe",
         r"C:\Users\*\AppData\Roaming\AnyDesk\AnyDesk.exe"]),
    ("LogMeIn",
        [r"SOFTWARE\LogMeIn"],
        [r"C:\Program Files (x86)\LogMeIn\x64\LogMeIn.exe"]),
    ("RustDesk",
        [],
        [r"C:\Program Files\RustDesk\rustdesk.exe",
         r"C:\Users\*\AppData\Roaming\RustDesk\rustdesk.exe"]),
    ("Splashtop",
        [r"SOFTWARE\Splashtop Inc."],
        [r"C:\Program Files (x86)\Splashtop\Splashtop Remote\Client\SRClient.exe"]),
    ("RemotePC",
        [r"SOFTWARE\RemotePC"],
        [r"C:\Program Files (x86)\RemotePC\RemotePC.exe"]),
    ("ConnectWise Control",
        [r"SOFTWARE\ScreenConnect Client"],
        [r"C:\Program Files (x86)\ScreenConnect Client*\ScreenConnect.ClientService.exe"]),
    ("GoToMyPC",
        [r"SOFTWARE\Citrix\GoToMyPC"],
        [r"C:\Program Files (x86)\Citrix\GoToMyPC\*\g2mcomm.exe"]),
    ("Chrome Remote Desktop",
        [],
        [r"C:\Program Files (x86)\Google\Chrome Remote Desktop\*\remoting_host.exe"]),
    ("VNC Server",
        [r"SOFTWARE\RealVNC"],
        [r"C:\Program Files\RealVNC\VNC Server\vncserver.exe"]),
    ("UltraVNC",
        [],
        [r"C:\Program Files\uvnc bvba\UltraVNC\winvnc.exe"]),
    ("Parsec",
        [],
        [r"C:\Program Files\Parsec\parsecd.exe",
         r"C:\Program Files\Parsec\pservice.exe",
         r"C:\Users\*\AppData\Roaming\Parsec\parsecd.exe"]),
    ("BeyondTrust",
        [r"SOFTWARE\Bomgar"],
        [r"C:\Program Files\Bomgar\bomgar-scc.exe"]),
    ("Dameware",
        [r"SOFTWARE\SolarWinds\DameWare Mini Remote Control"],
        [r"C:\Program Files\SolarWinds\DameWare Mini Remote Control\DWRCC.exe"]),
    ("Supremo",
        [],
        [r"C:\Program Files\Supremo\Supremo.exe",
         r"C:\Program Files\Supremo\SupremoService.exe"]),
    ("Remote Utilities",
        [r"SOFTWARE\Remote Utilities"],
        [r"C:\Program Files\Remote Utilities - Host\rutserv.exe"]),
    ("Radmin",
        [r"SOFTWARE\Radmin"],
        [r"C:\Program Files\Radmin\Radmin.exe"]),
    ("AeroAdmin",
        [],
        [r"C:\Program Files\AeroAdmin\AeroAdmin.exe"]),
    ("LiteManager",
        [],
        [r"C:\Program Files\LiteManager\ROMServer.exe",
         r"C:\Program Files*\LiteManager*\ROMServer.exe",
         r"C:\Program Files*\LiteManager*\ROMViewer.exe"]),
    ("Zoho Assist",
        [r"SOFTWARE\ZohoMeetingManager"],
        []),
    ("ShowMyPC",
        [],
        [r"C:\Program Files\ShowMyPC\ShowMyPC.exe"]),
]

# -- Remote Monitoring & Management (RMM) Platforms ---------------------------
# Enterprise tools; flagged for awareness on unmanaged / consumer endpoints.
RMM_DETECTION = [
    ("ScreenConnect / ConnectWise",
        [r"SOFTWARE\ScreenConnect Client", r"SOFTWARE\ConnectWise"],
        [r"C:\Program Files (x86)\ScreenConnect Client*\ScreenConnect.ClientService.exe"]),
    ("Atera",
        [r"SOFTWARE\ATERA Networks"],
        [r"C:\Program Files\ATERA Networks\AteraAgent\AteraAgent.exe"]),
    ("Syncro",
        [r"SOFTWARE\RepairTech\Syncro"],
        [r"C:\Program Files\RepairTech\Syncro\Syncro.App.Runner.exe"]),
    ("Kaseya",
        [r"SOFTWARE\Kaseya"],
        [r"C:\Program Files (x86)\Kaseya\*\AgentMon.exe"]),
    ("NinjaRMM",
        [r"SOFTWARE\NinjaRMM"],
        [r"C:\Program Files (x86)\NinjaRMM\NinjaRMMAgent\ninjarmmagent.exe"]),
    ("Datto RMM",
        [r"SOFTWARE\CentraStage"],
        [r"C:\Program Files (x86)\CentraStage\CagService.exe"]),
    ("N-able N-sight",
        [r"SOFTWARE\N-able Technologies"],
        [r"C:\Program Files (x86)\N-able Technologies\Windows Agent\bin\agent.exe"]),
    ("ManageEngine",
        [r"SOFTWARE\ManageEngine\DesktopCentral"],
        [r"C:\Program Files\ManageEngine\DesktopCentral_Agent\bin\dcagentservice.exe"]),
    ("Pulseway",
        [r"SOFTWARE\Pulseway"],
        [r"C:\Program Files\Pulseway\Pulseway.exe"]),
    ("SuperOps",
        [r"SOFTWARE\SuperOps"],
        []),
]


# -- Packet Capture / Interface Dumping Software ----------------------------
# Format: (display_name, [registry_keys], [exe_paths])
DUMPING_SOFTWARE = [
    ("Wireshark",
        [r"SOFTWARE\Wireshark", r"SOFTWARE\WOW6432Node\Wireshark"],
        [r"C:\Program Files\Wireshark\Wireshark.exe"]),
    ("Npcap",
        [r"SOFTWARE\Npcap"],
        [r"C:\Program Files\Npcap\NPFInstall.exe"]),
    ("WinPcap",
        [r"SOFTWARE\WinPcap"],
        []),
    ("Microsoft Network Monitor",
        [r"SOFTWARE\Microsoft\Netmon3"],
        [r"C:\Program Files\Microsoft Network Monitor 3\netmon.exe"]),
    ("RawCap",
        [],
        [r"C:\Program Files\RawCap\RawCap.exe"]),
    ("SmartSniff",
        [],
        [r"C:\Program Files\NirSoft\SmartSniff\smsniff.exe"]),
    ("Fiddler",
        [r"SOFTWARE\Telerik\Fiddler"],
        [r"C:\Program Files\Fiddler\Fiddler.exe",
         r"C:\Users\*\AppData\Local\Programs\Fiddler\Fiddler.exe"]),
    ("Charles Proxy",
        [],
        [r"C:\Program Files\Charles\Charles.exe",
         r"C:\Program Files (x86)\Charles\Charles.exe"]),
]

# ============================================================================
# BROWSER DETECTION DATA
# ============================================================================

# Fallback version numbers used when live version fetch fails / is offline
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

# Engine type + discontinued status per browser name
BROWSER_META = {
    "Google Chrome":             {"engine": "Chromium", "discontinued": False},
    "Microsoft Edge":            {"engine": "Chromium", "discontinued": False},
    "Mozilla Firefox":           {"engine": "Gecko",    "discontinued": False},
    "Brave":                     {"engine": "Chromium", "discontinued": False},
    "Opera":                     {"engine": "Chromium", "discontinued": False},
    "Opera GX":                  {"engine": "Chromium", "discontinued": False},
    "Vivaldi":                   {"engine": "Chromium", "discontinued": False},
    "Arc":                       {"engine": "Chromium", "discontinued": False},
    "Chromium":                  {"engine": "Chromium", "discontinued": False},
    "SRWare Iron":               {"engine": "Chromium", "discontinued": False},
    "Yandex Browser":            {"engine": "Chromium", "discontinued": False},
    "UC Browser":                {"engine": "Chromium", "discontinued": True},
    "Avast Secure Browser":      {"engine": "Chromium", "discontinued": False},
    "AVG Secure Browser":        {"engine": "Chromium", "discontinued": False},
    "Torch":                     {"engine": "Chromium", "discontinued": True},
    "Slimjet":                   {"engine": "Chromium", "discontinued": False},
    "Comodo Dragon":             {"engine": "Chromium", "discontinued": False},
    "CoolNovo":                  {"engine": "Chromium", "discontinued": True},
    "Naver Whale":               {"engine": "Chromium", "discontinued": False},
    "Iridium":                   {"engine": "Chromium", "discontinued": False},
    "Epic Privacy Browser":      {"engine": "Chromium", "discontinued": False},
    "CentBrowser":               {"engine": "Chromium", "discontinued": False},
    "360 Browser":               {"engine": "Chromium", "discontinued": False},
    "Coc Coc":                   {"engine": "Chromium", "discontinued": False},
    "Firefox Developer Edition": {"engine": "Gecko",    "discontinued": False},
    "Waterfox":                  {"engine": "Gecko",    "discontinued": False},
    "LibreWolf":                 {"engine": "Gecko",    "discontinued": False},
    "Zen Browser":               {"engine": "Gecko",    "discontinued": False},
    "Tor Browser":               {"engine": "Gecko",    "discontinued": False},
    "Pale Moon":                 {"engine": "Gecko",    "discontinued": False},
    "SeaMonkey":                 {"engine": "Gecko",    "discontinued": False},
    "K-Meleon":                  {"engine": "Gecko",    "discontinued": False},
    "Basilisk":                  {"engine": "Gecko",    "discontinued": False},
    "IceCat":                    {"engine": "Gecko",    "discontinued": False},
    "Internet Explorer":         {"engine": "Trident",  "discontinued": True},
    "Safari":                    {"engine": "WebKit",   "discontinued": True},
    "Avant Browser":             {"engine": "Other",    "discontinued": True},
    "Lunascape":                 {"engine": "Other",    "discontinued": True},
    "Flock":                     {"engine": "Other",    "discontinued": True},
    "RockMelt":                  {"engine": "Other",    "discontinued": True},
    "Midori":                    {"engine": "Other",    "discontinued": True},
    "Maxthon":                   {"engine": "Chromium", "discontinued": False},
}

# Registry paths for browser version detection
# (name, reg_key, value_name, hive)
BROWSER_REGISTRY = [
    ("Google Chrome",        r"Software\Google\Chrome\BLBeacon",                  "version",        _winreg.HKEY_CURRENT_USER),
    ("Google Chrome",        r"SOFTWARE\Google\Chrome\BLBeacon",                  "version",        _winreg.HKEY_LOCAL_MACHINE),
    ("Microsoft Edge",       r"Software\Microsoft\Edge\BLBeacon",                 "version",        _winreg.HKEY_CURRENT_USER),
    ("Microsoft Edge",       r"SOFTWARE\Microsoft\Edge\BLBeacon",                 "version",        _winreg.HKEY_LOCAL_MACHINE),
    ("Mozilla Firefox",      r"SOFTWARE\Mozilla\Mozilla Firefox",                 "CurrentVersion", _winreg.HKEY_LOCAL_MACHINE),
    ("Brave",                r"Software\BraveSoftware\Brave-Browser\BLBeacon",    "version",        _winreg.HKEY_CURRENT_USER),
    ("Brave",                r"SOFTWARE\BraveSoftware\Brave-Browser\BLBeacon",    "version",        _winreg.HKEY_LOCAL_MACHINE),
    ("Opera",                r"Software\Opera Software",                           "Last Stable Install Path", _winreg.HKEY_CURRENT_USER),
    ("Opera GX",             r"Software\Opera Software\Opera GX Stable",          "Last Stable Install Path", _winreg.HKEY_CURRENT_USER),
    ("Vivaldi",              r"Software\Vivaldi",                                  "Version",        _winreg.HKEY_CURRENT_USER),
    ("Arc",                  r"Software\Arc\Arc",                                  "Version",        _winreg.HKEY_CURRENT_USER),
    ("Yandex Browser",       r"Software\Yandex\YandexBrowser\BLBeacon",           "version",        _winreg.HKEY_CURRENT_USER),
    ("Avast Secure Browser", r"Software\AVAST Software\Browser\BLBeacon",         "version",        _winreg.HKEY_CURRENT_USER),
    ("AVG Secure Browser",   r"Software\AVG\Browser\BLBeacon",                    "version",        _winreg.HKEY_CURRENT_USER),
    ("Internet Explorer",    r"SOFTWARE\Microsoft\Internet Explorer",              "svcVersion",     _winreg.HKEY_LOCAL_MACHINE),
    ("Waterfox",             r"SOFTWARE\Mozilla\Waterfox",                         "CurrentVersion", _winreg.HKEY_LOCAL_MACHINE),
]

# Filesystem exe paths for browser version detection (fallback to filesystem)
# (name, [paths])
BROWSER_EXE_PATHS = [
    ("Google Chrome",        [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                               r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]),
    ("Mozilla Firefox",      [r"C:\Program Files\Mozilla Firefox\firefox.exe",
                               r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"]),
    ("Brave",                [r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"]),
    ("Opera",                [r"C:\Program Files\Opera\launcher.exe",
                               os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera\launcher.exe")]),
    ("Opera GX",             [os.path.expandvars(r"%LOCALAPPDATA%\Programs\Opera GX\launcher.exe")]),
    ("Vivaldi",              [r"C:\Program Files\Vivaldi\Application\vivaldi.exe",
                               os.path.expandvars(r"%LOCALAPPDATA%\Vivaldi\Application\vivaldi.exe")]),
    ("Waterfox",             [r"C:\Program Files\Waterfox\waterfox.exe"]),
    ("Tor Browser",          [os.path.expandvars(r"%USERPROFILE%\Desktop\Tor Browser\Browser\firefox.exe")]),
    ("LibreWolf",            [r"C:\Program Files\LibreWolf\librewolf.exe"]),
    ("Chromium",             [os.path.expandvars(r"%LOCALAPPDATA%\Chromium\Application\chrome.exe")]),
    ("Pale Moon",            [r"C:\Program Files\Pale Moon\palemoon.exe"]),
    ("Maxthon",              [r"C:\Program Files\Maxthon\Bin\Maxthon.exe"]),
    ("Slimjet",              [r"C:\Program Files\Slimjet\slimjet.exe"]),
    ("Comodo Dragon",        [r"C:\Program Files\Comodo\Dragon\dragon.exe"]),
    ("SeaMonkey",            [r"C:\Program Files\SeaMonkey\seamonkey.exe"]),
    ("SRWare Iron",          [r"C:\Program Files\SRWare Iron\iron.exe",
                               r"C:\Program Files (x86)\SRWare Iron\iron.exe"]),
    ("Yandex Browser",       [os.path.expandvars(r"%LOCALAPPDATA%\Yandex\YandexBrowser\Application\browser.exe")]),
    ("UC Browser",           [os.path.expandvars(r"%LOCALAPPDATA%\UCBrowser\Application\UCBrowser.exe")]),
    ("Avast Secure Browser", [r"C:\Program Files\AVAST Software\Browser\Application\AvastBrowser.exe"]),
    ("AVG Secure Browser",   [r"C:\Program Files\AVG\Browser\Application\AVGBrowser.exe"]),
    ("Torch",                [os.path.expandvars(r"%LOCALAPPDATA%\Torch\Application\torch.exe")]),
    ("CoolNovo",             [r"C:\Program Files\CoolNovo\coolnovo.exe"]),
    ("Naver Whale",          [r"C:\Program Files\Naver\Naver Whale\Application\whale.exe"]),
    ("Iridium",              [r"C:\Program Files\Iridium\iridium.exe"]),
    ("Epic Privacy Browser", [r"C:\Program Files\Epic Privacy Browser\Application\epic.exe",
                               os.path.expandvars(r"%LOCALAPPDATA%\Epic Privacy Browser\Application\epic.exe")]),
    ("CentBrowser",          [os.path.expandvars(r"%LOCALAPPDATA%\CentBrowser\Application\chrome.exe")]),
    ("360 Browser",          [r"C:\Program Files\360\360Browser\360Chrome.exe"]),
    ("Coc Coc",              [os.path.expandvars(r"%LOCALAPPDATA%\CocCoc\Browser\Application\browser.exe")]),
    ("Firefox Developer Edition", [r"C:\Program Files\Firefox Developer Edition\firefox.exe"]),
    ("Zen Browser",          [r"C:\Program Files\Zen Browser\zen.exe"]),
    ("K-Meleon",             [r"C:\Program Files\K-Meleon\k-meleon.exe"]),
    ("Basilisk",             [r"C:\Program Files\Basilisk\basilisk.exe"]),
    ("IceCat",               [r"C:\Program Files\GNU IceCat\icecat.exe"]),
    ("Internet Explorer",    [r"C:\Program Files\Internet Explorer\iexplore.exe"]),
    ("Safari",               [r"C:\Program Files\Safari\Safari.exe",
                               r"C:\Program Files (x86)\Safari\Safari.exe"]),
    ("Avant Browser",        [r"C:\Program Files\Avant Browser\avant.exe"]),
    ("Lunascape",            [r"C:\Program Files\Lunascape\Lunascape.exe"]),
    ("Midori",               [r"C:\Program Files\Midori\midori.exe"]),
]


# ============================================================================
# NETWORK DETECTION DATA
# ============================================================================

# DNS servers worth alerting on when they appear unexpectedly.
# NOTE: These are not all "malicious." Some are legitimate filtering DNS
# providers. SystemShield should present them as "DNS changed / filtering /
# review required" unless paired with stronger compromise indicators.
KNOWN_BAD_DNS = [
    "198.51.100.1", "203.0.113.1", "192.0.2.1",      # RFC 5737 test-net placeholders; broken/misconfigured DNS if active

    # CleanBrowsing DNS filters
    "185.228.168.168", "185.228.169.168",             # CleanBrowsing Family Filter
    "185.228.168.10",  "185.228.169.11",              # CleanBrowsing Adult Filter
    "185.228.168.9",   "185.228.169.9",               # CleanBrowsing Security Filter
    "185.228.169.10",                                  # Legacy/needs validation; retained to avoid behavior change

    # OpenDNS / Cisco FamilyShield / Umbrella
    "208.67.222.123", "208.67.220.123",               # OpenDNS FamilyShield
    "146.112.61.104", "146.112.61.105",               # Cisco Umbrella block/redirect IPs

    # Retired / regional filtering DNS
    "199.85.126.20",  "199.85.127.20",                # Norton ConnectSafe policy B; retired/discontinued
    "77.88.8.7",      "77.88.8.3",                    # Yandex Family DNS
]


# ============================================================================
# PROGRAM CLASSIFICATION DATA
# ============================================================================

# Publisher substrings used to mark an installed program as a Windows /
# system component rather than user-installed software.
SYSTEM_PUBLISHERS = [
    'microsoft', 'windows', 'intel', 'nvidia', 'amd', 'realtek', 'qualcomm',
    'broadcom', 'synaptics', 'conexant', 'dolby', 'maxx audio',
]


# ============================================================================
# SOURCE-BACKED DETECTION NOTES
# ============================================================================
# Optional metadata for review/documentation. Existing scanner logic can ignore
# this constant. Keep tuple schemas above unchanged unless System_Scanner.py is
# updated to consume richer metadata.

DETECTION_SOURCE_NOTES = {
    "policy": {
        "purpose": "Passive risk reporting and remediation guidance; not malware removal.",
        "threat_level_rule": (
            "Threat level should be based on category + context. Remote access/RMM "
            "tools are high-risk when unexpected on unmanaged consumer endpoints, "
            "but legitimate in managed IT environments. DNS filters are review/warning "
            "items unless the user did not approve the change."
        ),
    },
    "sources": {
        "windows_uninstall_registry": "https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key",
        "windows_service_wmi": "https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service",
        "cisa_rmm_misuse": "https://www.cisa.gov/news-events/alerts/2023/01/25/cisa-nsa-and-ms-isac-release-advisory-malicious-use-rmm-software",
        "ftc_tech_support_scams": "https://consumer.ftc.gov/articles/how-spot-avoid-and-report-tech-support-scams",
    },
    "source_backed_values_added": {
        "Parsec": {
            "executables": ["parsecd.exe", "pservice.exe"],
            "source": "https://support.parsec.app/hc/en-us/articles/32381199341716-Parsec-App-for-Windows",
            "confidence": "High",
            "note": "Official Parsec documentation names loader parsecd.exe and service pservice.exe.",
        },
        "Supremo": {
            "executables": ["Supremo.exe", "SupremoService.exe"],
            "source": "https://www.supremocontrol.com/support/tutorials/how-to-run-supremo-multiple-instances-terminal-server/",
            "confidence": "Medium",
            "note": "Official Supremo documentation names Supremo.exe and SupremoService.exe; exact install path should be VM-confirmed.",
        },
        "LiteManager": {
            "executables": ["ROMServer.exe", "ROMViewer.exe"],
            "source": "https://litemanager.com/download/",
            "confidence": "Medium",
            "note": "Official LiteManager download page names server/viewer modules; exact install folder varies by edition.",
        },
        "Charles Proxy": {
            "executables": ["Charles.exe"],
            "source": "https://www.charlesproxy.com/documentation/installation/",
            "confidence": "Medium",
            "note": "Official docs confirm Windows installer/menu install; x86/x64 paths should be VM-confirmed.",
        },
        "CleanBrowsing DNS": {
            "dns": [
                "185.228.168.168", "185.228.169.168",
                "185.228.168.10", "185.228.169.11",
                "185.228.168.9", "185.228.169.9",
            ],
            "source": "https://cleanbrowsing.org/filters",
            "confidence": "High",
            "note": "Legitimate filtering DNS; alert as unexpected DNS/filtering, not malware by itself.",
        },
        "OpenDNS FamilyShield": {
            "dns": ["208.67.222.123", "208.67.220.123"],
            "source": "https://www.opendns.com/setupguide/",
            "confidence": "High",
            "note": "Legitimate FamilyShield filtering DNS; alert as unexpected DNS/filtering, not malware by itself.",
        },
    },
    "vm_required_before_hard_detection": [
        "SoftEther VPN registry key",
        "HMA VPN executable path",
        "TorGuard registry key",
        "IVPN registry key",
        "AirVPN registry key",
        "StrongVPN executable path",
        "Proton Pass executable path",
        "Zoho Vault executable path",
        "mSecure executable path",
        "SafeInCloud executable path",
        "Chrome Remote Desktop install registry key",
        "RustDesk registry key",
        "UltraVNC registry key",
        "Parsec registry key",
        "Zoho Assist unattended/service executable path",
        "SuperOps agent executable path",
        "RawCap storage path",
        "SmartSniff storage path",
    ],
}
