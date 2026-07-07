# Threat-Hunting-Scenario-Crosscheck

## RDP Compromise Incident

**Report ID:** INC-2026-

**Analyst:** Nadezna Morris

**Date:** 17-January-2026

**Incident Date:** 

---

## Executive Summary

---

## 1. Findings

### **Key Indicators of Compromise (IOCs):**

| Type                          | Indicator                                                                 |
| ----------------------------- | --------------------------------------------------------------------------|


---

***FLAG 1 – Initial Endpoint Association***

**Objective:** Determine which endpoint first shows activity tied to the user context involved in the chain.

**Flag:** `sys1-dept`
```
DeviceProcessEvents
| where InitiatingProcessAccountName has_any ("5y51-d3p7")
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, ProcessId, InitiatingProcessId
| order by TimeGenerated asc
```
<img width="872" height="96" alt="image" src="https://github.com/user-attachments/assets/75641f0a-7b5d-4380-853e-e7bf22c42535" />

---

***FLAG 2 – Remote Session Source Attribution***

**Objective:** Identify the remote session source information tied to the initiating access on the first endpoint.

**Flag:** `192.168.0.110`
```
DeviceNetworkEvents
| where InitiatingProcessAccountName == "5y51-d3p7"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| project TimeGenerated, DeviceName, RemoteIP, LocalIP, RemotePort, InitiatingProcessRemoteSessionIP
| order by TimeGenerated asc
```
<img width="871" height="96" alt="image" src="https://github.com/user-attachments/assets/33e4b2c8-fc4f-4468-9a2a-e72bc55171a3" />

---

***FLAG 3 – Support Script Execution Confirmation***

**Objective:** Confirm execution of a support-themed PowerShell script from a user-accessible directory.

**Flag:** `"powershell.exe" -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1`
```
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has ".ps1"
| where ProcessCommandLine has @"\Users\"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="998" height="92" alt="image" src="https://github.com/user-attachments/assets/724c6df9-b429-44d6-b0cc-75983df71a10" />

---

***FLAG 4 – System Reconnaissance Initiation***

**Objective:** Identify the first reconnaissance action used to gather host and user context.

**Flag:** `"whoami.exe" /all`
```
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where AccountName != "system"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="700" height="72" alt="image" src="https://github.com/user-attachments/assets/5d29a190-784b-414b-9b68-6ba9fb6fcb5f" />

---

***FLAG 5 – Sensitive Bonus-Related File Exposure***

**Objective:** Identify the first sensitive year-end bonus-related file that was accessed during exploration.

**Flag:** `BonusMatrix_Draft_v3.xlsx`
```
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where ProcessCommandLine has_any ("bonus", "salary", "payroll", "xlsx", "csv")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="922" height="92" alt="image" src="https://github.com/user-attachments/assets/20d9c186-27ad-40cd-902a-8f00d9628b15" />

---

***FLAG 6 – Data Staging Activity Confirmation***

**Objective:** Confirm that sensitive data was prepared for movement by staging into an export/archive output.

**Flag:** `2533274790396713`
```
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where ActionType == "FileCreated"
| where FileName has_any (".zip", ".rar", ".7z", ".tar", ".gz")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessUniqueId
| order by TimeGenerated desc 
```
<img width="1187" height="87" alt="image" src="https://github.com/user-attachments/assets/25f82bd6-b1f1-4f44-9be0-97750dfda133" />

---

***FLAG 7 – Outbound Connectivity Test***

**Objective:** Confirm that outbound access was tested prior to any attempted transfer.

**Flag:** `2025-12-03T06:27:31.1857946Z`
```
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by TimeGenerated desc 
```
<img width="812" height="78" alt="image" src="https://github.com/user-attachments/assets/d6519c13-8409-4b3d-b069-d9e67d586233" />

---

***FLAG 8 – Registry-Based Persistence***

**Objective:** Identify evidence of persistence established via a user Run key.

**Flag:** `HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
```
DeviceRegistryEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project TimeGenerated, DeviceName, RegistryValueName, RegistryKey
| order by TimeGenerated asc
```
<img width="1176" height="86" alt="image" src="https://github.com/user-attachments/assets/e61651da-1b52-4065-ac1a-53235a847fc0" />

---

***FLAG 9 – Scheduled Task Persistence***

**Objective:** Confirm a scheduled task was created or used to automate recurring execution.

**Flag:** `BonusReviewAssist`
```
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where FileName == "schtasks.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```
<img width="842" height="98" alt="image" src="https://github.com/user-attachments/assets/681fbd80-5a05-4de2-aea0-79125361e081" />

---

***FLAG 10 – Secondary Access to Employee Scorecard Artifact***

**Objective:** Identify evidence that a different remote session context accessed an employee-related scorecard file.

**Flag:** `YE-HELPDESKTECH`
```
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where InitiatingProcessRemoteSessionDeviceName != "" 
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessRemoteSessionDeviceName, RemoteIP, RemotePort
| sort by TimeGenerated desc
```
<img width="861" height="98" alt="image" src="https://github.com/user-attachments/assets/c6436c09-ca53-443b-a2fe-b21361748611" />

---

***FLAG 11 – Bonus Matrix Activity by a New Remote Session Context***

**Objective:** Identify another remote session device name that is associated with higher level related activities later in the chain.

**Flag:** `YE-HRPLANNER`
```
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where InitiatingProcessRemoteSessionDeviceName != "" 
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessRemoteSessionDeviceName, RemoteIP, RemotePort
| sort by TimeGenerated desc
```
<img width="890" height="92" alt="image" src="https://github.com/user-attachments/assets/904533e1-f038-4778-aa74-460215e24214" />

---

***FLAG 12 – Performance Review Access Validation***

**Objective:** Confirm access to employee performance review material through user-level tooling.

**Flag:** `2025-12-03T07:25:15.6288106Z`
```
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where ProcessCommandLine has_any ("employee", "review", "performance")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc 
```
<img width="952" height="76" alt="image" src="https://github.com/user-attachments/assets/02c8426c-319e-4607-a709-940b245d1391" />

---

***FLAG 13 – Approved/Final Bonus Artifact Access***

**Objective:** Confirm access to a finalized year-end bonus artifact with sensitive-read classification.

**Flag:** `2025-12-03T07:25:39.1653621Z`
```
DeviceEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-31))
| where ActionType == "SensitiveFileRead"
| project TimeGenerated, AccountSid, DeviceName, ActionType, FileName
| order by TimeGenerated desc 
```
<img width="902" height="75" alt="image" src="https://github.com/user-attachments/assets/c97e9968-255b-456f-9dd3-5b5b3f695969" />

---

***FLAG 14 – Candidate Archive Creation Location***

**Objective:** Identify where a suspicious candidate-related archive was created.

**Flag:** `C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip`
```
DeviceFileEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-6))
| where FileName has_any (".zip")
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated desc 
```
<img width="1202" height="82" alt="image" src="https://github.com/user-attachments/assets/672d298b-6706-48c2-93d2-b3b88aa53a4b" />

---

***FLAG 15 – Outbound Transfer Attempt Timestamp***

**Objective:** Confirm an outbound transfer attempt occurred after staging activity.

**Flag:** `2025-12-03T07:26:28.5959592Z`
```
DeviceNetworkEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-6))
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```
<img width="822" height="80" alt="image" src="https://github.com/user-attachments/assets/3002f789-5046-4149-83b5-3d5b0f7ba9e1" />

---

***FLAG 16 – Local Log Clearing Attempt Evidence***

**Objective:** Identify command-line evidence of attempted local log clearing.

**Flag:** `"wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational`
```
DeviceProcessEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-6))
| where FileName in~ ("wevtutil.exe", "powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("cl","Clear-EventLog","wevtutil")
| project TimeGenerated, DeviceName, ActionType, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="865" height="75" alt="image" src="https://github.com/user-attachments/assets/0902c993-ca23-49da-889f-b6fbe3e6d831" />

---

***FLAG 17 – Second Endpoint Scope Confirmation***

**Objective:** Identify the second endpoint involved in the chain based on similar telemetry patterns.

**Flag:** `main1-srvr`
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-6))
| where ProcessCommandLine has_any ("JavierR")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="882" height="75" alt="image" src="https://github.com/user-attachments/assets/9d26b78a-7e8c-4ad7-9be2-ef474a69b87a" />

---

***FLAG 18 – Approved Bonus Artifact Access on Second Endpoint***

**Objective:** Confirm the approved bonus artifact is accessed again on the second endpoint.

**Flag:** `2025-12-04T03:11:58.6027696Z`
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-03) .. datetime(2025-12-5))
| where DeviceName == "main1-srvr"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="836" height="78" alt="image" src="https://github.com/user-attachments/assets/07691f83-8f6e-48b7-a9af-cd50f92f69d3" />

---

***FLAG 19 – Employee Scorecard Access on Second Endpoint***

**Objective:** Confirm employee-related scorecard access occurs again on the second endpoint and identify the remote session device context.

**Flag:** `YE-FINANCEREVIE`
```
DeviceNetworkEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-6))
| where InitiatingProcessRemoteSessionDeviceName != ""
| project TimeGenerated, DeviceName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
<img width="757" height="77" alt="image" src="https://github.com/user-attachments/assets/c62d8417-f19e-4d8e-9a9c-18565193b65c" />

---

***FLAG 20 – Staging Directory Identification on Second Endpoint***

**Objective:** Identify the directory used for consolidation of internal reference materials and archived content.

**Flag:** `C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip`
```
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-6))
| where FileName has_any (".zip",".rar",".7z")
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc
```
<img width="1260" height="88" alt="image" src="https://github.com/user-attachments/assets/cc287d5b-31b1-4b51-bf99-d858b7a4ef2e" />

---

***FLAG 21 – Staging Activity Timing on Second Endpoint***

**Objective:** Determine when staging activity occurred during the final phase on the second endpoint

**Flag:** `2025-12-04T03:15:29.2597235Z`
```
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-6))
| where FileName has_any (".zip",".rar",".7z")
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc
```
<img width="1221" height="88" alt="image" src="https://github.com/user-attachments/assets/f7e99808-2128-4c50-a19e-2b5d4d68c73f" />

---

***Flag 22 – Outbound Connection Remote IP (Final Phase)***

**Objective:** Identify the remote IP associated with the final outbound connection attempt.

**Flag:** `54.83.21.156`
```
DeviceNetworkEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated between (datetime(2025-12-01) .. datetime(2025-12-6))
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, ActionType, RemoteIP, RemoteUrl, RemotePort
| order by TimeGenerated asc
```
<img width="776" height="76" alt="image" src="https://github.com/user-attachments/assets/d45857e7-9085-4f8d-a18a-f787394ceccf" />

---

## 2. Investigation Summary


---

## 3. MITRE ATT&CK Mapping



---

## 4. Recommendations

### Immediate Actions



### Short-term Remediations



### Long-term Remediations



---

**Report Status:** Complete  

**Next Review:**  

**Distribution:** Cyber Range
