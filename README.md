<h1 align="center"> WebGeeks SystemShield </h1>

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/d70e0ca3-8675-48e8-a33d-3d45f5d99dab"
    alt="WebGeeks SystemShield icon"
    width="150"
  />
</p>

<p align="center">
  <strong>A lightweight home system security auditing tool for Windows 10/11.</strong>
</p>

<p align="center">
  <a href="https://systemshield.net">Website</a>
  ·
  <a href="https://github.com/ImmaGundam/WebGeeks-SystemShield/releases">Releases</a>
</p>

<div align="center">
     |-------------------------------------------------------|<br>
     <b>Current Version:</b> 1.4.2 - <b>Release:</b> 6/11/2026<br>
     |-------------------------------------------------------|<br>
</div>
<br>
SystemShield is a lightweight security and system auditing
application designed to help users understand what may be putting their
computer at risk.

SystemShield reviews system settings, installed software, browser versions,
network configuration, hardware/runtime information, and security features,
then presents the results in a clear browser-based dashboard with expanded
remediation guidance.

It is designed to help identify:

- Potentially unwanted programs, also known as PUPs
- Network sniffing and packet capture tools
- Remote access tools and exposed remote access settings
- Remote monitoring and management tools on unmanaged systems
- Misconfigured firewall, DNS, VPN, or network settings
- Outdated browsers and vulnerable software indicators
- Disabled or weakened system security features
- Long system uptime that may call for a proper restart

SystemShield is not an antivirus, malware remover, or endpoint protection
platform. It is a reporting and auditing tool that helps users review system
health, security posture, and configuration risks. SystemShield includes a
heuristic detection list focused on identifying common security and
configuration risks, including legitimate applications with known
vulnerabilities, potentially unwanted programs, capture & network software,
browser toolbars, junkware, remote access tools, RMM tools, and suspicious
utilities.



## Screenshots

Screenshots are organized by app page.

---

<div align="center">
  
<details>
<summary><strong>Dashboard</strong></summary>
<img width="1446" height="793" alt="dash" src="https://github.com/user-attachments/assets/cd8b7bf3-7b13-446c-999f-1393ded12d82" />
<br>
</details>

---

<details>
<summary><strong>System Information</strong></summary>

<img width="1446" height="793" alt="Screenshot 2026-06-11 204659" src="https://github.com/user-attachments/assets/30a87a34-c586-43d8-b613-cd5e15693513" />


</details>

---

<details>
<summary><strong>Apps & Programs</strong></summary>

<img width="1446" height="793" alt="Screenshot 2026-06-11 204703" src="https://github.com/user-attachments/assets/498caf30-b363-4451-ba5d-fcb96227a4f3" />


</details>

---

<details>
<summary><strong>Network Security</strong></summary>

<img width="1446" height="793" alt="network" src="https://github.com/user-attachments/assets/33b0bcf0-4a95-4f7f-bbe9-abe0a92899f1" />


</details>

---

<details>
<summary><strong>Remediation Analysis</strong></summary>

<img width="1446" height="793" alt="Screenshot 2026-06-11 204756" src="https://github.com/user-attachments/assets/d73fbee5-dd36-4555-acec-19f55a535b37" />

</details>

---

<details>
<summary><strong>VirusTotal</strong></summary>

<img width="1446" height="793" alt="Screenshot 2026-06-11 204714" src="https://github.com/user-attachments/assets/04dacd64-f28f-4f8b-b5c8-29314f536a63" />


</details>

---

<details>
<summary><strong>About</strong></summary>

<img width="1446" height="793" alt="Screenshot 2026-06-11 204717" src="https://github.com/user-attachments/assets/2a6225ac-0e5f-42ed-a918-50cb3ddca13c" />

</details>

</div>

---

## Key Features

### System Security Review

- Detects Windows version, build, and system configuration
- Reviews Microsoft Defender status
- Checks firewall profile configuration
- Reports Windows Update status
- Reviews Secure Boot, TPM, BitLocker, and related system protections
- Evaluates user account, UAC, lock screen, guest account, and auto-login indicators

### Hardware & Runtime Profile

- Displays system manufacturer and model when available
- Displays device type when detectable
- Lists CPU, GPU, memory, storage, power profile, and uptime information
- Shows manufacturer and model values where Windows exposes them without administrator privileges
- Uses `Undetected` when a value cannot be safely read without elevated access

### Software & Browser Analysis

- Lists installed desktop programs
- Reviews Microsoft Store apps
- Detects known unwanted or risky software
- Detects remote access, RMM, packet capture, proxy, and related tools
- Checks installed browser versions
- Flags outdated, discontinued, or suspicious software indicators

### Network Configuration Review

- Displays Internet and VPN status in a compact overview
- Displays network adapter information in collapsed interface cards
- Reports local and public IP details
- Checks DNS configuration
- Detects possible DNS hijacking or DNS review indicators
- Identifies VPN usage and network-related anomalies
- Detects packet capture and interface dumping tools

### Remediation Analysis

- Builds a remediation profile from available scan sources
- Separates System, Software, and Network findings
- Shows the value found, evidence type, and detected path/registry/service data when available
- Provides plain-language explanations for each finding
- Uses Windows Settings shortcuts and Windows-registered uninstall entries for remediation guidance

### Risk Reporting

- Separates findings into risks and recommendations
- Provides shorthand dashboard alerts for quick review
- Provides expanded remediation details on the Remediation Analysis page
- Helps users understand what each issue means
- Generates audit-style PDF reports for documentation
- Apps & Programs report output defaults to the top 30 programs in the current sort order, with an option to include all detected programs

### VirusTotal Support

- Optional VirusTotal lookup support
- Hash-based file lookup support
- File upload support for additional analysis
- Displays lookup and scan results in an in-app result popup
- Uses the user's VirusTotal API key only for the current lookup session
- Does not save VirusTotal API keys to disk

> **Note:** VirusTotal lookups are controlled by the user's own VirusTotal API
> key and VirusTotal account terms. Do not upload private, confidential, or
> sensitive files unless you are permitted to submit them.

---
## What SystemShield Checks

SystemShield reviews several areas of system health and security:

| Area | Examples |
|---|---|
| Operating system | Version, build, update status |
| Security features | Defender, firewall, BitLocker, TPM, Secure Boot |
| User security | Account settings, password indicators, lock behavior |
| Hardware | System model, CPU, GPU, memory, storage, power profile, uptime |
| Software | Installed apps, PUP indicators, remote access tools, RMM tools |
| Browsers | Installed browsers and version status |
| Network | Internet/VPN overview, adapters, IP details, DNS, suspicious settings |
| Remediation | Windows Settings shortcuts, registered uninstall entries, guidance |
| Reporting | Risks, recommendations, remediation analysis, PDF export, top-30/all app report options |

---

## Detection Coverage

SystemShield currently tracks **216 unique software/browser/tool names** across
its detection categories, plus **18 DNS review entries**.

| Detection group | Count |
|---|---:|
| PUP / bloatware | 17 |
| Scamware | 7 |
| Torrent / P2P clients | 10 |
| Crypto miners | 14 |
| Hacking / pentest utilities | 12 |
| Data transfer / exfil tools | 10 |
| Remote shell tools | 7 |
| RAT / malware frameworks | 14 |
| Credential stealers | 5 |
| VPN clients | 25 |
| Password managers | 16 |
| Remote access tools | 21 |
| RMM platforms | 10 |
| Packet capture / proxy tools | 8 |
| Browsers | 42 |

| Summary | Count |
|---|---:|
| Raw entries across categories | 218 |
| Unique software/browser/tool names | 216 |
| DNS review entries | 18 |


## Project Structure
<details>

```
```text
WebGeeks-SystemShield/

Backend | Logic
├── main.py Application         # entrypoint, version metadata, Windows integration, and exposed UI actions.
├── core/version.py Composes    # MainProgram.EngineVersion.DetectionVersion application metadata.
├── core/webview_bridge.py      # Pywebview window startup, embedded host configuration, and Python-to-JavaScript bridge dispatch.
├── core/system_utils.py        # Shared helpers such as get_ps, ps_first, registry reads, version parsing, and formatting helpers.
├── core/scan_helpers.py        # Shared scan helpers used across detection modules.
├── core/scan_system.py         # Core perform_scan() orchestration and Windows baseline collection.
├── core/browser_versions.py    # Live browser version-track fetching, in-memory TTL caching, normalization, and fallback baselines.
├── core/browser_scan.py        # Browser detection, local version reads, latest-version fetchers, browser status evaluation, and browser update actions.
├── core/program_scan.py        # Uninstall entry enumeration, software classification, flagged program detection, and uninstaller launch helpers.
├── core/network_scan.py        # Network adapters, DNS, VPN detection, remote access exposure, and related checks.
├── core/summary_builder.py     # Summary payload generation for export / PDF and user-facing report assembly.
├── core/detection_data.py      # Detection/reference data only.

Front-end | UI
├── PyWebview ]
|
├── ui/index.html               # Main application shell, shared runtime, modal containers, and page loading flow.
├── ui/bridge.js                # Frontend bridge that maps UI calls onto the pywebview API.
├── ui/main.cs                  # Shared light-theme layout, component, and utility styling.
├── ui/main-dark.css            # Shared dark-theme overrides.
├── ui/pages/dashboard.html     # Dashboard page structure and page-specific presentation.
├── ui/pages/dashboard.css
├── ui/pages/sysinfo.html       # System Information page structure and page-specific presentation.
├── ui/pages/sysinfo.css
├── ui/pages/programs.html      # Apps & Programs page structure and page-specific presentation.
├── ui/pages/programs.css 
├── ui/pages/network.html       # Network Security page structure and page-specific presentation.
├── i/pages/network.css 
├── ui/pages/remediation.html   # Remediation page structure and page-specific presentation.
├── ui/pages/remediation.css 
├── ui/pages/virustotal.html    # VirusTotal page structure and page-specific presentation.
├── ui/pages/virustotal.css 
├── ui/pages/about.html         # About page structure and page-specific presentation.
├── ui/pages/about.css 

Powered by:
├──  Python: Scanner / detection logic
├──  HTML/CSS/JavaScript: UI
├──  PyWebView — API
├──  PowerShell — inline PowerShell command strings through Python
├──  PyInstaller — Packager for distribution

```

</details>


---

## Important Notes

- SystemShield does not need administrator privileges to run.
- SystemShield is designed for auditing, reporting, and Windows-based remediation guidance.
- It does not replace antivirus or endpoint protection software.
- It does not remove files directly.
- Software actions use Windows-registered uninstall entries or Windows Settings shortcuts.
- Results should be reviewed in context before making system changes.
- PDF reports use the current Apps & Programs sort order. Program output defaults to the top 30 entries unless the user enables all detected programs.
- VirusTotal functionality requires the user to provide their own API key.
- VirusTotal API keys are used only for the current lookup session and are not saved by SystemShield.
- This project is provided as freeware and is openly developed to be transparent in its purpose and operation.
- Use, redistribution, and modification are governed by the included `License.txt` file.

---

## How to Use

### Option 1: Standalone Executable

1. Go to the **Releases** page.
2. Download the latest compiled `.exe`.
3. Run SystemShield.
4. Start a scan from the dashboard.

No installation is required.

### Option 2: Run from Source

#### Requirements

- Windows 10 / Windows 11
- Python 3.x
- Run `main.py`
  
#### Install dependencies

```bash
pip install pywebview psutil wmi pywin32
```

#### Run

```bash
python main.py
```


## License

See `License.txt` for license information.
