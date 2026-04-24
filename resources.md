# Resources

References, tools, and further reading for "Threat Hunting Safari: An Intelligence-Driven Hunt for APT33."

---

## Threat Intelligence Sources

### Primary CTI Report
- **Microsoft Threat Intelligence** — [Peach Sandstorm deploys new custom Tickler malware in long-running intelligence gathering operations](https://www.microsoft.com/en-us/security/blog/2024/08/28/peach-sandstorm-deploys-new-custom-tickler-malware-in-long-running-intelligence-gathering-operations/) (August 28, 2024)

### MITRE ATT&CK
- **APT33 Group Profile** — [G0064](https://attack.mitre.org/groups/G0064/)
- **ATT&CK Navigator** — [navigator.mitre.org](https://mitre-attack.github.io/attack-navigator/) (create layers from the techniques below)

### Additional APT33 / Peach Sandstorm Reporting
- Microsoft — [Peach Sandstorm password spray campaigns enable intelligence collection at high-value targets](https://www.microsoft.com/en-us/security/blog/2023/09/14/peach-sandstorm-password-spray-campaigns-enable-intelligence-collection-at-high-value-targets/) (September 2023)
- Mandiant — [APT33: New Insights into Iranian Cyber Espionage Group](https://www.mandiant.com/resources/blog/apt33-insights-into-iranian-cyber-espionage)
- Symantec — [Elfin: Relentless Espionage Group Targets Multiple Organizations in Saudi Arabia and U.S.](https://symantec-enterprise-blogs.security.com/threat-intelligence/elfin-apt33-espionage)
- CISA — [Iranian Government-Sponsored APT Actors](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-321a)

---

## MITRE ATT&CK Techniques Referenced

| Technique ID | Name | Hunt Context |
|-------------|------|-------------|
| T1059 | Command and Scripting Interpreter | a1.exe spawning cmd.exe, PowerShell |
| T1033 | System Owner/User Discovery | whoami → Administrator.SCYTHE |
| T1082 | System Information Discovery | systeminfo, sysinfo module |
| T1083 | File and Directory Discovery | dir C:\\, dir Documents |
| T1049 | System Network Connections Discovery | net use |
| T1016 | System Network Configuration Discovery | Get-DnsClientServerAddress, arp |
| T1007 | System Service Discovery | services --all |
| T1518.001 | Security Software Discovery | Get-CimInstance AntiVirusProduct (root/SecurityCenter2) |
| T1003 | OS Credential Dumping | LaZagne + reg save SAM/SYSTEM/SECURITY hives |
| T1555 | Credentials from Password Stores | LaZagne browser/WiFi/OS credential harvest |
| T1003.001 | LSASS Memory | lazagne.exe → lsass.exe (GrantedAccess: 0x1FFFFF) |
| T1105 | Ingress Tool Transfer | peaches.zip downloaded via C2, lazagne.exe downloaded separately |
| T1036.007 | Masquerading: Double File Extension | tickler.pdf.exe |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | HKCU\...\Run → "SharePoint" = "SharePoint.exe" |
| T1219 | Remote Access Software | AnyDesk deployed from Downloads\APT33\vfs\ |
| T1087.002 | Account Discovery: Domain Account | ADExplorer -snapshot → domain_var_snapshot.dat |
| T1552.001 | Credentials in Files | AD snapshot contains credential-adjacent data |
| T1560.001 | Archive Collected Data: Archive via Utility | Compress-Archive → results.zip |
| T1041 | Exfiltration Over C2 Channel | results.zip exfiltrated over primary C2 (port 443) |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | net use with stolen credentials → lateral movement |

---

## Detection Rules (Sigma)

All 12 Sigma rules used in this talk are in `sigma_rules/` at the root of this repo. They can be translated to any SIEM using the tools below.

| Rule File | Title | Detects | ATT&CK | Author |
|-----------|-------|---------|--------|--------|
| `file_event_win_susp_double_extension.yml` | Suspicious Double Extension Files | Files written to disk with double extensions (.pdf.exe, .doc.exe, etc.) | T1036.007 | Nasreddine Bencherchali, frack113 |
| `win_proc_creation_double_extension.yml` | Process Creation With Double File Extension | Process launched where Image or ParentImage has a double extension | T1036.007 | Micah Babinski |
| `proc_creation_win_susp_cmd_posh_parentimage.yml` | Suspicious CMD/POSH ParentImage | cmd.exe or powershell.exe spawned from a parent outside System32 / Program Files | T1059.001, T1059.003 | Tyler Casey, SCYTHE |
| `proc_creation_win_lolbas_discovery.yml` | Suspicious LOLBAS Discovery Commands | Common discovery binaries: whoami, net, systeminfo, ipconfig, arp, netstat, schtasks | T1059 | Tyler Casey |
| `proc_creation_win_sus_img_location.yml` | Suspicious Process Creation Location | Process executing from or parented to Downloads, Temp, AppData\Local, Public | T1059.001 | Tyler Casey, SCYTHE |
| `reg_set_win_run_keys.yml` | Set Run Key Registry Value | Modifications to HKCU/HKLM ...\CurrentVersion\Run and RunOnce keys | T1547.001 | Tyler Casey, SCYTHE |
| `proc_creation_win_hktl_lazagne.yml` | HackTool - LaZagne Execution | LaZagne by image name, known import hashes, suspicious path + module flags | T1555, T1003 | Nasreddine Bencherchali, Swachchhanda Poudel |
| `proc_creation_win_remote_access_tools_anydesk.yml` | Remote Access Tool - AnyDesk Execution | AnyDesk execution by image name, product description, or company metadata | T1219 | frack113 |
| `proc_creation_win_remote_access_tools_anydesk_susp_exec.yml` | AnyDesk Execution From Suspicious Folder | AnyDesk running outside AppData or Program Files | T1219 | Florian Roth (Nextron Systems) |
| `proc_creation_win_RAS_nonstandard_folder.yml` | RAS Executed from Non-standard Directories | AnyDesk, TeamViewer, or ScreenConnect running outside standard install paths | T1219 | Tyler Casey, SCYTHE |
| `proc_creation_win_sysinternals_adexplorer_execution.yml` | AD Database Snapshot Via ADExplorer | ADExplorer.exe with the `-snapshot` flag | T1003.003, T1552.001 | Nasreddine Bencherchali |
| `file_event_win_susp_archive_creation.yml` | Suspicious Archive Creation | Archive file (.zip, .7z, .tar, .wim) created by a process that is not a standard archive utility | T1560.001 | Tyler Casey, SCYTHE |

### Sigma Translation Tools
- **sigma-cli** — [github.com/SigmaHQ/sigma-cli](https://github.com/SigmaHQ/sigma-cli) — translate rules to Splunk SPL, Elastic, Microsoft Sentinel, and more
- **Sigconverter.io** — [sigconverter.io](https://sigconverter.io/) — web-based Sigma rule translator, no install required
- **SigmaHQ Repository** — [github.com/SigmaHQ/SigmaHQ](https://github.com/SigmaHQ/SigmaHQ) — full community rule collection

---

## Event IDs Used

### Sysmon

| EID | Category | What We Hunted |
|-----|----------|---------------|
| 1 | Process Creation | Process trees, command lines, parent-child relationships — the backbone of every hunt |
| 3 | Network Connection | C2 callbacks (a1.exe → 13.58.116.24:443), AnyDesk relay connections, ADExplorer LDAP to DC |
| 10 | Process Access | LSASS access by LaZagne (GrantedAccess: 0x1FFFFF = PROCESS_ALL_ACCESS) |
| 11 | File Create | Tool staging (tickler.pdf.exe, sold.dll, lazagne.exe), archive creation (results.zip) |
| 13 | Registry Value Set | Run key persistence — HKCU\...\Run → "SharePoint" = "SharePoint.exe" |
| 22 | DNS Query | C2 domain resolution (training.stage.unicorncroft.com), AnyDesk relay domains |

### Windows PowerShell

| EID | Category | What We Hunted |
|-----|----------|---------------|
| 4103 | Module/Command Invocation | sold.dll orchestration proof — shows the DLL loaded in-process by tickler.pdf.exe driving the persistence chain (invisible to Sysmon EID 1 alone) |
| 4104 | Script Block Logging | PowerShell commands: Get-CimInstance, Compress-Archive, Expand-Archive, Get-DnsClientServerAddress |

---

## Tools & Platforms

### Hunting & Detection
| Tool | Description | Link |
|------|-------------|------|
| Splunk | SIEM and log analysis platform | [splunk.com](https://www.splunk.com/) |
| Splunk Community Edition | Free version for personal/lab use | [splunk.com/en_us/download](https://www.splunk.com/en_us/download/splunk-enterprise.html) |
| Sigma | Open-source generic detection rule format | [github.com/SigmaHQ](https://github.com/SigmaHQ/SigmaHQ) |

### Endpoint Telemetry
| Tool | Description | Link |
|------|-------------|------|
| Sysmon | Enhanced Windows system monitoring | [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| SwiftOnSecurity Sysmon Config | Well-maintained community Sysmon configuration — recommended starting point | [github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) |
| Olaf Hartong Sysmon Modular | Modular, customizable Sysmon configuration | [github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) |

### Adversary Emulation
| Tool | Description | Link |
|------|-------------|------|
| SCYTHE | Adversary emulation platform used to generate all telemetry in this talk | [scythe.io](https://scythe.io) |
| SCYTHE Community Threats | Free threat packages | [github.com/scythe-io/community-threats](https://github.com/scythe-io/community-threats) |

### Tools Observed in the Emulation
| Tool | Adversary Use | Legitimate Use / Source |
|------|-------------|----------------|
| LaZagne | Credential harvesting — browsers, WiFi, OS credential stores, SAM/SYSTEM/SECURITY hive dumps | [github.com/AlessandroZ/LaZagne](https://github.com/AlessandroZ/LaZagne) |
| AnyDesk | Backup C2 / hands-on-keyboard access via relay infrastructure | [anydesk.com](https://anydesk.com/) |
| ADExplorer | AD -snapshot for offline schema analysis — all users, groups, GPOs, trusts | [Sysinternals ADExplorer](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer) |

---

## Further Reading

### Threat Hunting Methodology
- SANS — [A Practical Model for Conducting Cyber Threat Hunting](https://www.sans.org/white-papers/38710/)
- Sqrrl (now AWS) — [A Framework for Cyber Threat Hunting](https://www.threathunting.net/sqrrl-archive)
- David Bianco — [The Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
- Chris Brenton — [Threat Hunting with the MITRE ATT&CK Framework](https://www.activecountermeasures.com/threat-hunting-with-the-mitre-attck-framework/)

### Detection Engineering
- Florian Roth — [How to Write Sigma Rules](https://github.com/SigmaHQ/SigmaHQ/wiki/How-to-Write-Sigma-Rules)
- MITRE Cyber Analytics Repository — [car.mitre.org](https://car.mitre.org/)
- Elastic Detection Rules — [github.com/elastic/detection-rules](https://github.com/elastic/detection-rules)

### Iranian Threat Landscape
- Recorded Future — [Iran Cyber Operations Overview](https://www.recordedfuture.com/research/iran)
- Microsoft — [Nation-state threat actor profiles](https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/)
- CrowdStrike — [2024 Global Threat Report](https://www.crowdstrike.com/global-threat-report/)

---

## IOCs from the Emulation

> **Note:** The file/path/registry IOCs below are from our controlled adversary emulation in a lab environment. The Tickler hashes and Azure domains in the Real-World section are from Microsoft's August 2024 report and represent actual threat actor infrastructure.

### Lab Emulation IOCs

| Type | Value | Context |
|------|-------|---------|
| File | tickler.pdf.exe | Tickler backdoor — double extension masquerading |
| File | sold.dll | Second-stage DLL loaded in-process by Tickler; orchestrates persistence |
| File | SharePoint.bat | Persistence batch script — sets Run key named "SharePoint" |
| File | peaches.zip | Toolkit delivery archive (emulation name for Network Security.zip) |
| File | lazagne.exe | Open-source credential harvester |
| File | lazagne_results.txt | LaZagne credential dump output |
| File | results.zip | Compressed credential dump staged for exfiltration |
| File | domain_var_snapshot.dat | Full offline Active Directory snapshot from ADExplorer |
| File | a1.exe | C2 implant — root parent of all post-compromise activity |
| IP | 13.58.116.24 | Primary C2 server (port 443) |
| Domain | training.stage.unicorncroft.com | C2 staging domain |
| Domain | relay-*.net.anydesk.com | AnyDesk relay infrastructure (backup C2) |
| Registry | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SharePoint | Persistence Run key |
| Path | C:\Users\...\Downloads\APT33\vfs\ | Adversary tool staging directory |
| GrantedAccess | 0x1FFFFF | PROCESS_ALL_ACCESS on lsass.exe — credential theft confirmed |
| Port | 443 | All C2 and AnyDesk relay traffic |
| Port | 389 | ADExplorer LDAP connection to Domain Controller |

### Real-World Tickler IOCs (Microsoft Report, August 2024)

**Tickler malware samples:**

| SHA-256 | File | Description |
|---------|------|-------------|
| 7eb2e9e8cd450fc353323fd2e8b84fbbdfe061a8441fd71750250752c577d198 | YAHSAT NETWORK_INFRASTRUCTURE_SECURITY_GUIDE_20240421.pdf.exe | Primary Tickler sample |
| ccb617cc7418a3b22179e00d21db26754666979b4c4f34c7fda8c0082d08cec4 | sold.dll | Second-stage Trojan dropper |
| 5df4269998ed79fbc997766303759768ce89ff1412550b35ff32e85db3c1f57b | batch script | Persistence batch script (sets SharePoint Run key) |
| fb70ff49411ce04951895977acfc06fa468e4aa504676dedeb40ba5cea76f37f | malicious DLL | Backdoor DLL (functionally identical to sold.dll) |
| 711d3deccc22f5acfd3a41b8c8defb111db0f2b474febdc7f20a468f67db0350 | malicious DLL | Backdoor DLL (second variant) |

**Azure C2 infrastructure (attacker-controlled Azure App Service apps):**

```
subreviews.azurewebsites[.]net
satellite2.azurewebsites[.]net
nodetestservers.azurewebsites[.]net
satellitegardens.azurewebsites[.]net
softwareservicesupport.azurewebsites[.]net
getservicessuports.azurewebsites[.]net
getservicessupports.azurewebsites[.]net
getsupportsservices.azurewebsites[.]net
satellitespecialists.azurewebsites[.]net
satservicesdev.azurewebsites[.]net
servicessupports.azurewebsites[.]net
websupportprotection.azurewebsites[.]net
supportsoftwarecenter.azurewebsites[.]net
centersoftwaresupports.azurewebsites[.]net
softwareservicesupports.azurewebsites[.]net
getsdervicessupoortss.azurewebsites[.]net
```

### Microsoft Defender XDR Hunting Queries (from Microsoft Report)

**Connectivity to Peach Sandstorm C2 infrastructure:**
```kql
let domainList = dynamic(["subreviews.azurewebsites.net","satellite2.azurewebsites.net",
    "nodetestservers.azurewebsites.net","satellitegardens.azurewebsites.net",
    "softwareservicesupport.azurewebsites.net","getservicessuports.azurewebsites.net",
    "getservicessupports.azurewebsites.net","getsupportsservices.azurewebsites.net",
    "satellitespecialists.azurewebsites.net","satservicesdev.azurewebsites.net",
    "servicessupports.azurewebsites.net","websupportprotection.azurewebsites.net",
    "supportsoftwarecenter.azurewebsites.net","centersoftwaresupports.azurewebsites.net",
    "softwareservicesupports.azurewebsites.net","getsdervicessupoortss.azurewebsites.net"]);
DeviceNetworkEvents
| where RemoteUrl has_any(domainList)
| project Timestamp, Domain = RemoteUrl, DeviceName, InitiatingProcessFileName
```

**Malicious file activity (by hash):**
```kql
let fileHashes = dynamic([
    "711d3deccc22f5acfd3a41b8c8defb111db0f2b474febdc7f20a468f67db0350",
    "fb70ff49411ce04951895977acfc06fa468e4aa504676dedeb40ba5cea76f37f",
    "5df4269998ed79fbc997766303759768ce89ff1412550b35ff32e85db3c1f57b",
    "ccb617cc7418a3b22179e00d21db26754666979b4c4f34c7fda8c0082d08cec4",
    "7eb2e9e8cd450fc353323fd2e8b84fbbdfe061a8441fd71750250752c577d198"]);
DeviceFileEvents
| where SHA256 in (fileHashes)
| project Timestamp, FileHash = SHA256, FileName, DeviceName
```
