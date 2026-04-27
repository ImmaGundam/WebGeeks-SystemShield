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

---

## Overview

**WebGeeks SystemShield** is a lightweight security and system auditing
application designed to help users understand what may be putting their
computer at risk.

SystemShield reviews system settings, installed software, browser versions,
network configuration, and security features, then presents the results in a
clear browser-based dashboard.

It is designed to help identify:

- Potentially unwanted programs, also known as PUPs
- Network sniffing and packet capture tools
- Remote access tools and exposed remote access settings
- Misconfigured firewall, DNS, or network settings
- Outdated browsers and vulnerable software indicators
- Disabled or weakened system security features

SystemShield is not an antivirus, malware remover, or endpoint protection
platform. It is a reporting and auditing tool that helps users review system
health, security posture, and configuration risks. SystemShield includes a 
heuristic detection list focused on identifying common security and 
configuration risks, including legitimate applications with known 
vulnerabilities, potentially unwanted programs, capture & network software, 
browser toolbars, junkware, and suspicious utilities.

---

## Key Features

### System Security Review

- Detects Windows version, build, and system configuration
- Reviews Microsoft Defender status
- Checks firewall profile configuration
- Reports Windows Update status
- Reviews Secure Boot, TPM, BitLocker, and related system protections
- Evaluates user account and lock screen security indicators

### Software & Browser Analysis

- Lists installed desktop programs
- Reviews Microsoft Store apps
- Detects known unwanted or risky software
- Checks installed browser versions
- Flags outdated or suspicious software indicators

### Network Configuration Review

- Displays network adapter information
- Reports local and public IP details
- Checks DNS configuration
- Detects possible DNS hijacking indicators
- Identifies VPN usage and network-related anomalies

### Risk Reporting

- Separates findings into risks and recommendations
- Provides plain-language explanations
- Helps users understand what each issue means
- Generates audit-style reports for documentation

### VirusTotal Support

- Optional VirusTotal API key integration
- Hash-based file lookup support
- File upload support for additional analysis

> **Note:** VirusTotal API keys are stored locally in the executable directory
> when entered. Remove saved keys before sharing the application folder.

---

<h2 align="center">Dashboard Preview</h2>
<p align="center">
SystemShield displays scan results in an interactive local dashboard.<br><br>
 <img
    src="https://github.com/user-attachments/assets/3e13a8d6-6432-4f6e-9745-34b7fa4ea6a3"
    alt="SystemShield Dashboard"
    width="450"
  />
  <br>
</p>

## Project Structure

```text
WebGeeks-SystemShield/
├── .github/workflows/       # GitHub workflow files
├── docs/                    # Documentation and supporting files
├── web/                     # HTML, CSS, and JavaScript frontend
├── System_Scanner.py        # Main Python scanner application
├── detection_lists.py       # Detection lists and software indicators
├── logo.ico                 # Application icon
├── License.txt              # Project license
└── README.md                # Project overview
```

---

## Technology Stack

- **Python** — scanner logic and system checks
- **HTML/CSS/JavaScript** — local dashboard interface
- **Eel** — connects the Python backend to the web-based UI
- **PowerShell** — system-level Windows checks
- **PyInstaller** — standalone executable packaging

---

## What SystemShield Checks

SystemShield reviews several areas of system health and security:

Area | Examples 
- Operating system | Version, build, architecture, update status 
- Security features | Defender, firewall, BitLocker, TPM, Secure Boot 
- User security | Account settings, password indicators, lock behavior 
- Software | Installed apps, PUP indicators, remote access tools 
- Browsers | Installed browsers and version status 
- Network | Adapters, IP details, DNS, VPN, suspicious settings 
- Reporting | Risks, recommendations, and exportable results 

---

## Important Notes

- Does not need administrator privledges to run. 
  - Teaches you that it's a bad habit.
- SystemShield is designed for auditing and reporting.
- It does not replace antivirus or endpoint protection software.
- Results should be reviewed in context before making system changes.
- VirusTotal functionality requires the user to provide their own API key.
- This project is provided as freeware and is openly developed for
  transparency, documentation, and practical use.
- Use, redistribution, and modification are governed by the included
  `License.txt` file.

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
- Run 'System_Scanner.py'
  
#### Install dependencies

```bash
pip install eel psutil wmi pywin32
```

#### Run

```bash
python System_Scanner.py
```

---

## Roadmap

Future improvements:

- Expanded software detection lists
- Improved browser version detection
- More detailed remediation guidance
- Better PDF report formatting
- Additional network configuration checks

---

## License

See `License.txt` for license information.
