# WebGeeks - SystemShield
https://immagundam.github.io/WebGeeks-SystemShield/<br><br>
SystemShield is a Windows home security auditing application designed to provide users with a clear and comprehensive overview of their computer’s health compared to a defined baseline. It detects for potentially unwanted programs, network sniffing/capture tools, known malicious applications as well as misconfigured or malicious network settings that lead to DNS hijacking.
SystemShield is a standalone app made in Python (backend/logic) and HTML/CSS/JS (frontend/UI). 
I made this program to be simple and helpful for non-tech saavy people. There is a compiled .exe that includes all that is needed in a small (<30mb) package.

The tool scans your system and identifies:

- Operating system version, build, and security settings/features
- User account security, password protection, and lock screen settings
- Drive encryption and hardware details (CPU, RAM, motherboard)
- Windows Update and Defender status, including 3rd Party Antivirus and firewall statuses
- Storage devices, space used by installed programs and Microsoft Store apps
- Detects installed browsers for versions/out of date software. Assists staying up-to-date
- Detects for installed Potentionally-unwanted-software (PUPS) in a large list of over 50+ known bad software (Will receive regular updates)
- Detects for unwanted Remote access software and enabled remote desktop configurations
- Reports all identified issues as risks or suggestions providing explanations on how to fix them, or guiding the user in system to setting to fix.
- Scans network configuration and reports network adapters, and network configurations, showing private and public IP configs.
- Detects for VPNs and displays connection status/DNS
- Detects for hijacked/malicious DNS configurations and network scanning/dumping software.
- Generates detailed scan results in a professional security audit–style report format (export to PDF)
- VirusTotal Page: Upload files directly from your system for scan. Plug in your API key, upload files and pull file/hash results.

## Dashboard<br>
<i>All results are displayed in an interactive front-end powered by a browser interface.</i><br>
![1](https://github.com/user-attachments/assets/1867f21a-8c26-484c-a888-1fbe0ebc22dd)

## Apps & Programs
<i>Will detect and report bad/vulnerable software</i><br>
![2-1](https://github.com/user-attachments/assets/1a018ca5-78e1-4cb6-af5f-9880a3aa6f9e)

## Network Security
<img width="1027" height="307" alt="image" src="https://github.com/user-attachments/assets/4bebe7d0-87d3-4245-a0ec-b50ea7175622" />

---

Currently the main audience is Windows. SystemShield should work on any system that can run python, but currently development is focused on finishing on Windows first.

# How to Use:
### Option 1: (exe)

Windows users can download and run the .exe
Compiled using pyinstaller with required dependencies, it's a standalone running executable.
Note: If you plug in your VirusTotal API Key and copy the EXE, it will retain it. Please delete keys before sharing. 

### Option 2: (running in Python)

You will need:
- Windows 10 / 11
- Python 3.x

Also Required:<br>
eel <br>
psutil <br>
wmi<br>

Run:<br>
pip install eel psutil wmi<br>
