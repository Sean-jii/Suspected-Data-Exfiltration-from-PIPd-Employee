# Suspected-Data-Exfiltration-from-PIPd-Employee
An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP).  Your task is to investigate John's activities on his corporate device (windows-target-1) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

 Notes / Findings:

Timeline Summary and Findings:

I did search within MDE DeviceFileEvents for any activities with zip files, and found a lot of regular activity of archiving stuff and moving to a “backup” folder: 

<img width="327" height="83" alt="image" src="https://github.com/user-attachments/assets/5142e216-4be1-4c1d-9b98-dc15666a902f" />

<img width="921" height="408" alt="image" src="https://github.com/user-attachments/assets/88c6bb3c-27ea-40ef-904e-e3788e6fc448" />

—-------

I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for anything happening 2 minutes before the archive was created and 2 minutes after. I discovered around the same time that powershell installed 7zip and then used 7zip to zip up empoyee data into an archive:

<img width="564" height="146" alt="image" src="https://github.com/user-attachments/assets/6d9727a1-cfc6-4779-9d95-7c241d037a59" />

<img width="933" height="20" alt="image" src="https://github.com/user-attachments/assets/08f73f58-bde2-4a1c-ac4a-5f83279d800e" />

<img width="873" height="21" alt="image" src="https://github.com/user-attachments/assets/c79126e8-3e19-4257-81b7-7dba0b150ee3" />

<img width="928" height="43" alt="image" src="https://github.com/user-attachments/assets/0df8c285-d8c3-4cda-857e-7e7e1c9a81ec" />

—-------

I searched around the same time period for any evidence of exfiltration from the network, but I didn’t see any logs indicating as such: 

<img width="619" height="146" alt="image" src="https://github.com/user-attachments/assets/8f78bcc8-0df5-4eb5-9acd-2f003ffa2d2a" />

—-------


Response:

Immediately isolated the system upon discovering the archiving.

I relayed the information to the employees manager, including everything with the archives being created at regular intervals via powershell script. There didn’t appear to be any evidence of exfiltration. Standing by for further instruction from management. 

—--------

MITRE ATT&CK Framework TTPs:


## TA0002 – Execution  
- **T1059.001 – Command and Scripting Interpreter: PowerShell**  
  - PowerShell was used to silently install 7-Zip and execute a ZIP-archiving script.

## TA0004 – Privilege Escalation / Credential Access (if local accounts used)  
- **T1078.003 – Valid Accounts: Local Accounts** *(only if a local account was used for script execution / installation)*

## TA0005 – Defense Evasion  
- **T1027 – Obfuscated Files or Information**  
  - Use of scripted, possibly non-interactive PowerShell + installer may indicate attempts to obfuscate or hide malicious behavior.  

## TA0006 – Credential Access / TA0009 – Collection  
- **T1105 – Ingress Tool Transfer**  
  - The silent installation of 7-Zip could represent an external tool being brought into the environment for use.  
- **T1560.001 – Archive Collected Data: Archive via Utility**  
  - Use of 7-Zip to compress data into archives aligns with data staging behavior prior to potential exfiltration.

## TA0007 – Discovery / Collection (supporting behavior)  
- **T1049 – System Network Connections Discovery** *(if there was discovery prior to scanning)* — though not explicitly observed, port-scan activity suggests network discovery intent.

## TA0009 – Collection  
- **T1074.001 – Data Staged: Local Data Staging**  
  - Creation of ZIP archives (staging the data locally) before any exfiltration or transfer attempt.




