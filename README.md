# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Reginald-D/threat-hunting/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

DeviceFileEvents query results confirm Tor Browser installation completed on February 7, 2026 at 8:40:03 PM on endpoint win-11-2026. The creation of installation artifacts, including the license file tor.txt at C:\Users\admin2040\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses, validates successful extraction and deployment to the user's Desktop directory.



**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "win-11-2026"
| where FileName contains "tor"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```
<img width="1494" height="133" alt="image" src="https://github.com/user-attachments/assets/34221d46-428c-409f-8f9b-7e84857a650b" />
---

### 2. Searched the `DeviceProcessEvents` Table

Analysis of DeviceProcessEvents logs confirms that on February 7, 2026 at 8:39:40 PM, user admin2040 executed the Tor Browser installer from the Downloads folder. The process was launched with the /S flag, which triggers silent installation mode—automatically completing the installation without user prompts or visual confirmation dialogs.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "win-11-2026"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.5.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName, ProcessCommandLine
```
<img width="703" height="267" alt="image" src="https://github.com/user-attachments/assets/e8242f22-cf0b-42fb-9bb7-c7b24396affb" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
// TOR Browser or service was launched
DeviceProcessEvents
| where DeviceName == "win-11-2026"
| where ProcessCommandLine has_any ("tor.exe","firefox.exe", "tor-browser.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine, SHA256
```
<img width="845" height="196" alt="image" src="https://github.com/user-attachments/assets/2295611e-519b-4a8a-805c-1cbc705b12fb" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| where DeviceName == "win-11-2026"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<img width="1391" height="309" alt="image" src="https://github.com/user-attachments/assets/0ad3d062-0f5e-4a6f-a96f-1d86151a022a" />

---

# Chronological Event Timeline 


# Phase 1: Preparation & Execution
### 8:38:40 PM - Command Prompt Launched

- **Event Type:** ProcessCreated
- **Action:** User opened `cmd.exe` (Command Prompt)
- **Parent Process:** `explorer.exe`
- **Significance:** Command-line environment prepared for silent installation
  
### 8:39:40 PM - Tor Browser Installer Executed
- **Event Type:** ProcessCreated
- **KQL Query:** DeviceProcessEvents (installation detection)
- **Action:** admin2040 executed `tor-browser-windows-x86_64-portable-15.0.5.exe /S`
- **Location:** `C:\Users\admin2040\Downloads\`
- **Method:** Silent installation mode (/S flag)
- **File Hash (SHA256):** 15448e951583b624c3f8fdfa8bc55fa9b65e1bcafd474f3f2dfd5444e4178846
- **Significance:** Installation began without user prompts or GUI windows

# Phase 2: Installation Completion
### 8:40:03 PM - Installation Files Extracted
- **Event Type:** FileCreated
- **KQL Query:** DeviceFileEvents (file creation detection)
- **Action:** Tor Browser files extracted to Desktop
- **File Created:** tor.txt (license file)
- **Full Path:** `C:\Users\admin2040\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\tor.txt`
- **Significance:** Installation successfully completed (23 seconds from execution to completion)

# Phase 3: Service Initialization
### 8:40:48 PM - Tor Anonymization Service Started
- **Event Type:** ProcessCreated
- **KQL Query:** DeviceProcessEvents (Tor service detection)
- **Action:** `tor.exe` launched with full configuration
- **Key Configuration:**
  - **SOCKS Proxy:** `localhost:9150` (for Firefox)
  - **Control Port:** `localhost:9151` (for Tor management)
  - **Data Directory:** `C:\Users\admin2040\Desktop\Tor Browser\`
  - **Password Protected:** Yes (hashed password configured)
- **Significance:** Tor network service became fully operational (45 seconds after installation, 68 seconds from initial execution)


# Phase 4: Anonymous Browsing Activated
### 8:41:18 PM - First Browser Connection to Tor
- **Event Type:** NetworkConnectionEstablished
- **KQL Query:** DeviceNetworkEvents (network activity detection)
- **Action:** `firefox.exe` → `localhost:9150` (local SOCKS proxy)
 - **Protocol:** `SOCKS5` proxy connection
 - **Significance:** User initiated browsing session; Firefox connected to local Tor service
### 8:41:39 PM - Tor Circuit Building Begins
- **Event Type:** NetworkConnectionEstablished
- **Action:** `tor.exe` → `94.16.115.121:9001` (Tor relay node #1)
- **Relay Hostname:** `zl35v3.com`
- **Significance:** First hop in anonymous circuit established
### 8:41:40 PM - Additional Relay Connection
- **Event Type:** NetworkConnectionEstablished
- **Action:** tor.exe → 94.16.115.121:9001 (confirmation)
- **Relay URL:** https://www.zl35v3.com
### 8:41:42 PM - Second Relay Node Contacted
- **Event Type:** NetworkConnectionEstablished
- **Action:** tor.exe → 205.185.121.177:9001 (Tor relay node #2)
- **Significance:** Multi-hop circuit being constructed
### 8:41:44 PM - Third Relay Node Contacted (Multiple Connections)
- **Event Type:** NetworkConnectionEstablished (3 simultaneous connections)
- **Actions:**
  - tor.exe → `87.106.134.107:9001` (Tor relay node #3)
  - tor.exe → `87.106.134.107:9001` (relay: zw6w4hj5plv6ui3hnqeqjow.com)
  - tor.exe → `205.185.121.177:9001` (relay: fivgqmsmahhbsah6wha4oi.com)
- **Significance:** Complete Tor circuit established through 3 relay nodes
### 8:42:00 PM - Active Anonymous Browsing Session Confirmed
- **Event Type:** NetworkConnectionEstablished
- **Action:** `firefox.exe` → `localhost:9150` (SOCKS proxy)
- **Significance:** User actively browsing through fully established Tor network; all traffic now encrypted and anonymized

# Total Time to Full Operational Capability
### From execution to anonymous browsing: 3 minutes, 20 seconds
### Key Milestones:
- Installation: 23 seconds
- Service initialization: 68 seconds
- Network anonymization: 3 minutes 20 seconds

# Evidence Sources
### All events documented using the following KQL queries:
- **DeviceFileEvents** - Installation file creation detection
- **DeviceProcessEvents** - Installer execution and Tor service launch
- **DeviceNetworkEvents** - Tor network connections and browsing activity
- **Data Completeness:** Full kill chain documented from initial execution through active anonymous browsing

- This timeline can be inserted into your "Evidence" section to show the complete progression of events in a clear, chronological format.


---

# Summary
- On February 7, 2026, user `admin2040` installed and activated Tor Browser on device `win-11-2026`, achieving full anonymous browsing capability within 3 minutes and 20 seconds. The rapid, deliberate installation method and immediate operational use indicate prior familiarity with anonymization tools.
### Key Indicators of Deliberate Action:
- Silent installation mode (/S flag) used to bypass user prompts
- Remote access via RDP `IP: 10.0.8.8` with elevated administrator privileges
- Unusually fast deployment timeline suggests planned activity
- Immediate use upon installation completion
- Security Impact: Beginning at 8:42:00 PM, all network traffic from `admin2040` became completely anonymized and invisible to corporate security controls. Monitoring systems cannot detect websites visited, data exfiltration attempts, malicious downloads, dark web access, or inspect any encrypted Tor traffic.
- Recommendation: Immediate interview with `admin2040` required to determine authorization and intent. Forensic analysis of the endpoint recommended to identify scope of anonymous browsing activity and assess potential policy violations or data loss.


---

# Recommended Response Actions
- ***Immediate (0-24 Hours):*** Interview `admin2040` to determine if the Tor installation was authorized for legitimate security research or represents a policy violation. Preserve evidence by collecting browser artifacts, file access logs, and network traffic data before taking any containment actions. Verify the account is legitimate and review recent activity for data exfiltration indicators (large file transfers, USB usage, cloud uploads).
  
- ***Short-Term (1-7 Days):*** If unauthorized, remove Tor Browser, reset credentials, and revoke unnecessary admin privileges. Deploy EDR detection rules to alert on future Tor installations, silent installer executions, and connections to ports `9001` `9050` `9150`. Monitor `admin2040's` activity for 30 days with enhanced logging.
  
- ***Long-Term (Strategic):*** Implement application allowlisting to prevent unauthorized software installations, deploy Privileged Access Management (PAM) for admin account control, and block Tor exit nodes at the firewall. Conduct security awareness training on anonymization tool risks and acceptable use policies. The investigation outcome should drive the response—proportionate action for authorized research, swift containment for policy violations.


---
