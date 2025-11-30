# Suspected-Data-Exfiltration-from-PIPd-Employee
n employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP).  Your task is to investigate John's activities on his corporate device (windows-target-1) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

 Notes / Findings:

Timeline Summary and Findings:

I did search within MDE DeviceFileEvents for any activities with zip files, and found a lot of regular activity of archiving stuff and moving to a “backup” folder: 

DeviceFileEvents
| where DeviceName == "seanji-slowdown"
| where FileName endswith ".zip"
| order by Timestamp desc
