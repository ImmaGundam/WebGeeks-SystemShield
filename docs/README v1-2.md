\\\\\\\\\\\\\\\\\\\\\\\\\\
\\\\\\\\\\\\\\\\\\\\\\\\\\ 
| 	WebGeeks		     |
| 	SystemShield		 |
|           v1.2.1		 |
|	      *3/26/26*		 |
|	*www.webgeeks.org* 	 |
\\\\\\\\\\\\\\\\\\\\\\\\\\
\\\\\\\\\\\\\\\\\\\\\\\\\\

Version sequence is broken down to:

v\[Engine].\[BugRelease].\[DatabaseVer]

Updates:

* Increased detection list to 215 entries (Documentation 'detection_database.xlsx' in Repo)
* Adjusted detection logic, dictionary list now resides in "detection_list.py"
* Multi-GPU/CPU detection & result on dashboard (previously only detected primary CPU/GPUs)

Fixes:

* Detection logic wasn't detecting OpenSSH service correctly
* CSS color corrections in dark-mode
* TPM / Secure boot on Windows 11 & 10 not reporting correctly
* Lock screen not reporting "Good/green" when it does time-out - previously was as suggestion

About:

SystemShield is built in Python (backend/logic), PowerShell (a little), HTML, CSS and JavaScript (frontend/UI).

pip install -r requirements.txt

/////////////////////////////////

You will need:

* Windows 10 / Windows 11
* Python v3.10+

/////////////////////////////////

* Install with pip -

eel
psutil
wmi
pywin32

