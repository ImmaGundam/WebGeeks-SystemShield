# WebGeeks - SystemShield

SystemShield is mainly a Windows-focused security and system auditing application. It provides a comprehensive snapshot of your system's security settings, hardware, software, and potential risks. Will work on any platform with python. The tool identifies:

- Operating system version, build, and security features
- Antivirus and firewall status
- User account security, password protection, and lock screen settings
- Installed programs and Microsoft Store apps
- Browsers and password managers installed
- Remote access software and potential security risks
- Drive encryption and hardware details (CPU, RAM, motherboard)
- Windows Update and Defender status

All results are displayed in an interactive front-end powered by a browser interface.

![ss1](https://github.com/user-attachments/assets/e458266e-cc77-4002-9ee5-a1340a7e2454)

---

## Features

- Deep System Scan: Checks on OS, security settings, and hardware.
- Risk Analysis: Identifies potential vulnerabilities (weak passwords, disabled UAC, inactive firewall, unencrypted drives, etc.).
- Browser & Risky Software Detection: Highlights outdated browsers and known password managers.
- Remote Software Detection: Flags software that can allow remote access to your system.
- Hardware Info: CPU, RAM, motherboard, and storage statistics.
- Interactive Front-End: Displays results in a clean, user-friendly interface.

## Requirements
Chrome (Temporary, or change line 567 mode='chrome' with 'firefox' or 'edge')

You will need:
- Python 3.x
- pip

Also Required:<br>
eel <br>
psutil <br>
wmi<br>

Run:<br>
pip install eel psutil wmi<br>
