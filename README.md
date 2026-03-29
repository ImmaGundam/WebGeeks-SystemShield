# WebGeeks - SystemShield  
https://immagundam.github.io/WebGeeks-SystemShield/

---

## Overview

**SystemShield** is a lightweight Windows 10 & 11 security auditing application designed to provide a clear, comprehensive overview of your system’s security posture compared to a defined baseline.

It identifies potential risks including:
- Potentially Unwanted Programs (PUPs)
- Network sniffing and capture tools
- Known malicious or vulnerable software
- Misconfigured or malicious network settings (such as DNS hijacking)

SystemShield is built with a **Python backend** and a **HTML/CSS/JavaScript frontend**, delivered as a **portable standalone executable (<20MB)** — no installation required.

Designed with simplicity in mind, SystemShield makes security insights accessible to both technical and non-technical users.

---

## Key Features

### 🖥️ System & Security Analysis
- Detects OS version, build, and enabled security features
- Evaluates user account security (passwords, lock screen, timeout settings)
- Identifies drive encryption status and hardware details (CPU, RAM, motherboard)
- Checks Windows Update and Microsoft Defender status
- Detects third-party antivirus and firewall configurations

### 📦 Software & Storage Insights
- Analyzes installed programs and Microsoft Store apps
- Displays storage usage by application
- Identifies outdated browsers and software versions

### ⚠️ Threat Detection
- Detects **50+ known PUPs and unwanted software**
- Identifies remote access tools and exposed RDP configurations
- Flags network sniffing/capture tools and suspicious utilities

### 🌐 Network Security Analysis
- Reports network adapters and configurations
- Displays public and private IP details
- Detects VPN usage and DNS configurations
- Identifies potential **DNS hijacking or malicious configurations**

### 📊 Reporting & Remediation
- Categorizes findings as **Risks** or **Recommendations**
- Provides explanations and guidance to resolve issues
- Generates **professional audit-style reports (PDF export)**

### 🔍 VirusTotal Integration
- API key integration
- Upload files directly for analysis
- Retrieves hash-based scan results

---

## Dashboard
*All results are displayed in an interactive browser-based UI.*

![screen-01](https://github.com/user-attachments/assets/3e13a8d6-6432-4f6e-9745-34b7fa4ea6a3)

*Works on both Windows 10 & 11*

<img width="958" height="423" alt="1a0beb1e-0b16-49e7-815e-f726f1dfff3d" src="https://github.com/user-attachments/assets/2fa2e891-c249-4a96-b0b9-183e50e0aa59" />

---

* Detects exploitable & unwanted software *

![screen-05](https://github.com/user-attachments/assets/23679e62-0034-4940-a137-93dba3b44dd4)

<img width="899" height="81" alt="screen-08" src="https://github.com/user-attachments/assets/53a1ff0f-69c7-408a-91ba-4905ec4a1a40" />

---

# How to Use

## Option 1: Standalone Executable (.exe)
- Download and run the compiled executable
- Built using PyInstaller with all dependencies included
- No installation required

⚠️ **Note:** If a VirusTotal API key is entered, it will persist in the executable directory. Remove keys before sharing.

---

## Option 2: Run from Source (Python)

### Requirements:
- Windows 10 / 11  
- Python 3.x  

### Dependencies:
- eel
- psutil
- wmi
