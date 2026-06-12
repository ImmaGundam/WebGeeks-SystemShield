# SystemShield v1.4.2

- Replaced browser version hardcoding for Firefox Developer Edition with live upstream version resolution, cached browser track normalization, and safer fallback handling.
- Split page-specific markup and styles into dedicated HTML and CSS assets to reduce cross-page styling overlap.
- Reworked the System Information layout into grouped dashboard-style sections with overflow hints, storage row flow, and repositioned power profile details.
- Tightened dashboard scan-state centering plus recommended-action spacing and alignment to keep result cards stable during scanning.
- Replaced the previous external browser host with a pywebview desktop host backed by the embedded Windows WebView2 runtime and a native application bridge.


## Backend layout

- `main.py`
  Application entrypoint, version metadata, Windows integration, and exposed UI actions.
- `core/version.py`
  Composes `MainProgram.EngineVersion.DetectionVersion` application metadata.
- `core/webview_bridge.py`
  Pywebview window startup, embedded host configuration, and Python-to-JavaScript bridge dispatch.
- `core/system_utils.py`
  Shared helpers such as `get_ps`, `ps_first`, registry reads, version parsing, and formatting helpers.
- `core/scan_helpers.py`
  Shared scan helpers used across detection modules.
- `core/scan_system.py`
  Core `perform_scan()` orchestration and Windows baseline collection.
- `core/browser_versions.py`
  Live browser version-track fetching, in-memory TTL caching, normalization, and fallback baselines.
- `core/browser_scan.py`
  Browser detection, local version reads, latest-version fetchers, browser status evaluation, and browser update actions.
- `core/program_scan.py`
  Uninstall entry enumeration, software classification, flagged program detection, and uninstaller launch helpers.
- `core/network_scan.py`
  Network adapters, DNS, VPN detection, remote access exposure, and related checks.
- `core/summary_builder.py`
  Summary payload generation for export / PDF and user-facing report assembly.
- `core/detection_data.py`
  Detection/reference data only.

## Frontend layout

- `ui/index.html`
  Main application shell, shared runtime, modal containers, and page loading flow.
- `ui/bridge.js`
  Frontend bridge that maps UI calls onto the pywebview API.
- `ui/main.css`
  Shared light-theme layout, component, and utility styling.
- `ui/main-dark.css`
  Shared dark-theme overrides.
- `ui/pages/dashboard.html` and `ui/pages/dashboard.css`
  Dashboard page structure and page-specific presentation.
- `ui/pages/sysinfo.html` and `ui/pages/sysinfo.css`
  System Information page structure and page-specific presentation.
- `ui/pages/programs.html` and `ui/pages/programs.css`
  Apps & Programs page structure and page-specific presentation.
- `ui/pages/network.html` and `ui/pages/network.css`
  Network Security page structure and page-specific presentation.
- `ui/pages/remediation.html` and `ui/pages/remediation.css`
  Remediation page structure and page-specific presentation.
- `ui/pages/virustotal.html` and `ui/pages/virustotal.css`
  VirusTotal page structure and page-specific presentation.
- `ui/pages/about.html` and `ui/pages/about.css`
  About page structure and page-specific presentation.
