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


**Objective:**  

**Flag:**



**Objective:**  

**Flag:**



**Objective:**  

**Flag:**




**Objective:**  

**Flag:**




**Objective:**  

**Flag:**




**Objective:**  

**Flag:**




**Objective:**  

**Flag:**




**Objective:**  

**Flag:**




**Objective:**  

**Flag:**




**Objective:**  

**Flag:**



**Objective:**  

**Flag:**



**Objective:**  

**Flag:**




**Objective:**  

**Flag:**
