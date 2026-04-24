# Splunk Queries by Slide
## BSides KC — Threat Hunting Safari (39 Slides, v4)

Base filters for all queries:
- `index=main host=EC2AMAZ-SRGIV5B source="WinEventLog:Microsoft-Windows-Sysmon/Operational"`
- Adjust the time range to cover your emulation window

> **Tip:** Field names in Sysmon events are case-sensitive in some Splunk configurations. If a query returns no results, check actual field values by removing filters and inspecting raw events. Binary names may also differ (e.g., `AnyDesk.exe` vs `anydesk.exe`, `ADExplorer64.exe` vs `ADExplorer.exe`).

---

### Slide 13 — The Initial Hit (Double Extension File Detected)

**What it shows:** Sigma rule for double-extension file creation fires on tickler.pdf.exe — our hypothesis confirmed.

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=11
  TargetFilename="*.pdf.exe" OR TargetFilename="*.doc.exe" OR TargetFilename="*.jpg.exe"
| table _time host Image TargetFilename CreationUtcTime
| sort _time
```

**Why this matters:** One query, one hit, and the entire hunt is justified. This is intelligence-based hunting producing an actionable result from a single CTI artifact.

---

### Slide 14 — What We Found (Summary)

No new query — this slide summarizes the findings from Slide 13. Key fields to note in the result:
- `TargetFilename`: `C:\Users\Administrator.SCYTHE\Downloads\APT33\vfs\tickler.pdf.exe`
- `host`: `EC2AMAZ-SRGIV5B.scythe.lab`
- `EventCode`: 11 (File Create)

**Pivot:** From this hit we have three anchors — file, host, path — and we expand to all Sysmon events on the host.

---

### Slide 15 — Scoping the Endpoint (EventCode Breakdown)

**What it shows:** A landscape view of all Sysmon activity on the host, broken down by event type.

```spl
index=main host=EC2AMAZ-SRGIV5B source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode TaskCategory
| sort -count
```

**Why this matters:** This single query turns thousands of raw events into a structured map. Each row is an investigation thread. Run this immediately after finding your initial hit on any host.

---

### Slide 16 — What the Data Tells Us (EventCode Analysis)

No new query — this slide interprets the results from Slide 15. The counts in the talk:

| EID | Category | Count | Significance |
|-----|----------|-------|-------------|
| 11 | File Create | 2,532 | Extensive tool staging |
| 3 | Network Connection | 776 | Sustained C2 activity |
| 1 | Process Creation | 137 | 137 commands to investigate |
| 22 | DNS Query | 16 | Domain resolutions to map |
| 13 | Registry Value Set | 5 | Small = high signal for persistence |
| 10 | Process Access | 1 | Almost certainly LSASS access |

**Pivot:** Start with EID 1 (Process Creation) — it's the backbone of the host-based hunt.

---

### Slide 17 — Hunt 1: Process Creation (EID 1) — Building the Execution Chain

**What it shows:** Parent-child process relationships that reveal a1.exe as the root of all activity.

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=1
| eval ParentName=replace(ParentImage,".*\\\\","")
| eval ImageName=replace(Image,".*\\\\","")
| stats values(CommandLine) as Commands by ParentName ImageName
| sort ParentName ImageName
```

Alternative — filtered to a1.exe as parent to show direct children only:

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=1 ParentImage="*\\a1.exe"
| table _time Image CommandLine
| sort _time
```

**Why this matters:** This query produces the process tree. a1.exe appears as ParentImage for whoami, dir, net use, tickler.pdf.exe, lazagne.exe, anydesk.exe, ADExplorer.exe, and net use — a complete post-compromise playbook from one implant.

---

### Slide 18 — The Execution Chain (Process Tree)

No new query — this slide is the reconstructed process tree visualized from Slide 17 results. Key branches from a1.exe:
- Recon: `whoami`, `cmd /c dir C:\`, `cmd /c dir ...\Documents`, `net use`
- Malware: `tickler.pdf.exe` → `cmd.exe /c SharePoint.bat` → `reg add ...\Run /v SharePoint`
- Creds: `lazagne.exe all` → `reg save hklm\sam`, `reg save hklm\security`, `reg save hklm\system`
- RMM: `anydesk.exe --start`
- AD recon: `ADExplorer.exe -snapshot`
- Lat movement: `net use \\Host\Share /u:DOMAIN\User`

---

### Slide 19 — The Discovery Cascade

No new query — this slide tables the recon commands from the process tree. The full emulation recon sequence:

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=1 ParentImage="*\\a1.exe"
  (CommandLine="*whoami*" OR CommandLine="*dir*" OR CommandLine="*net use*"
   OR CommandLine="*Get-CimInstance*" OR CommandLine="*Get-DnsClient*"
   OR CommandLine="*services*" OR CommandLine="*arp*")
| table _time Image CommandLine
| sort _time
```

**Key behavioral signal:** Multiple discovery commands from the same parent in rapid succession is not a user — it's automation. Volume + variety + speed = adversary recon pattern.

---

### Slide 20 — Hunt 2: Tool Staging (Files Written to Disk — EID 11)

**What it shows:** Everything the adversary wrote to disk in the APT33 staging directory, in chronological order.

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=11
  TargetFilename="*\\Downloads\\APT33\\*"
| table _time Image TargetFilename
| sort _time
```

**Why this matters:** Timestamps tell the staging story: archive lands → extracted → individual tools appear → output files created → output compressed. The lifecycle of a post-compromise toolkit, readable from EID 11 alone.

---

### Slide 21 — The Adversary Toolkit on Disk

No new query — this slide inventories all files from Slide 20. Key files and their roles:

| File | Role |
|------|------|
| peaches.zip | Toolkit delivery archive |
| tickler.pdf.exe | Primary backdoor (double extension) |
| sold.dll | Second-stage DLL — orchestrates persistence via PowerShell |
| SharePoint.bat | Sets HKCU Run key named "SharePoint" |
| lazagne.exe | Open-source credential harvester |
| AnyDesk.exe | Backup C2 / RMM tool |
| ADExplorer.exe | AD snapshot tool (Sysinternals) |
| lazagne_results.txt | Credential dump output |
| results.zip | Compressed creds staged for exfiltration |
| domain_var_snapshot.dat | Full offline AD schema |

**Pivot:** Were these tools staged only, or did they execute? Hunt 3 finds out.

---

### Slide 22 — Hunt 3: Persistence (EID 1 + EID 13)

**What it shows:** The tickler → sold.dll → SharePoint.bat → reg add execution chain, plus direct confirmation the Run key was written.

**Screenshot 1: Process chain — tickler → cmd → SharePoint.bat → reg add**

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=1
  (Image="*tickler*" OR Image="*SharePoint.bat*" OR CommandLine="*reg add*Run*"
   OR CommandLine="*SharePoint.bat*")
| table _time ParentImage Image CommandLine
| sort _time
```

**Screenshot 2: Registry Run key confirmed written (EID 13)**

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=13
  TargetObject="*\\CurrentVersion\\Run\\*"
| table _time Image TargetObject Details EventType
| sort _time
```

**Why this matters:** EID 1 shows the command ran. EID 13 confirms it succeeded. Together they give belt-and-suspenders confirmation of active persistence.

---

### Slide 23 — Hunt 3: Persistence (PowerShell EID 4103) — sold.dll Proof

**What it shows:** sold.dll invoking PowerShell to write SharePoint.bat and set the Run key — behavior invisible to Sysmon EID 1 because sold.dll runs in-process inside tickler.pdf.exe.

```spl
index=main host=EC2AMAZ-SRGIV5B
  source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
  ("*sold*" OR "*SharePoint*" OR "*tickler*")
| table _time Message
| sort _time
```

> **Note:** sold.dll does not appear as a separate process in Sysmon EID 1 because it loads in-process inside tickler.pdf.exe. PowerShell EID 4103 (Module/Command Invocation logging) is the only source that reveals DLL-level behavior here. This is why PowerShell logging is non-negotiable alongside Sysmon.

---

### Slide 24 — The Persistence Chain Confirmed

No new query — this slide summarizes the four-step chain validated across EID 1, EID 4103, and EID 13:

1. a1.exe spawns tickler.pdf.exe
2. tickler.pdf.exe loads sold.dll in-process
3. sold.dll runs cmd.exe /c SharePoint.bat
4. reg add → HKCU\...\Run → "SharePoint" = "SharePoint.exe" ✓ confirmed in EID 13

---

### Slide 25 — Hunt 3: Credential Harvesting (EID 1 + EID 10)

**What it shows:** LaZagne execution and direct LSASS access with PROCESS_ALL_ACCESS.

**Screenshot 1: LaZagne execution and registry hive dumps**

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=1
  (Image="*lazagne*" OR CommandLine="*lazagne*"
   OR CommandLine="*reg save*hklm\\sam*" OR CommandLine="*reg save*hklm\\security*"
   OR CommandLine="*reg save*hklm\\system*")
| table _time ParentImage Image CommandLine
| sort _time
```

**Screenshot 2: LSASS access (EID 10)**

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=10
  TargetImage="*lsass.exe"
| table _time SourceImage TargetImage GrantedAccess CallTrace
| sort _time
```

**Why this matters:** GrantedAccess value `0x1FFFFF` = PROCESS_ALL_ACCESS. Any non-system process opening lsass.exe with this access mask is performing credential theft. This is a standalone incident trigger.

---

### Slide 26 — Hunt 3: Credential Harvesting — Staging for Exfiltration

**What it shows:** Compress-Archive packaging LaZagne output for exfiltration.

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=1
  CommandLine="*Compress-Archive*"
| table _time ParentImage Image CommandLine
| sort _time
```

Alternative via PowerShell script block logging:

```spl
index=main host=EC2AMAZ-SRGIV5B
  source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
  EventCode=4104 "*Compress-Archive*"
| table _time Message
| sort _time
```

**Why this matters:** The speed between LaZagne execution and Compress-Archive running tells you this is scripted — an operator's playbook, not manual keystrokes.

---

### Slide 27 — What LaZagne Did (Credential Summary)

No new query — this slide consolidates the credential access findings:
- `lazagne.exe all` → harvests browsers, WiFi, OS credential stores
- `reg save hklm\sam`, `reg save hklm\system`, `reg save hklm\security` → offline SAM attack
- lsass.exe opened with GrantedAccess `0x1FFFFF` → in-memory creds harvested
- `Compress-Archive → results.zip` → staged for exfiltration

**Pivot:** Adversary has valid credentials. Next: did they use them? Hunt 4.

---

### Slide 28 — Hunt 4: AnyDesk, ADExplorer, Net Use (Combined Query)

**What it shows:** Execution of all three remaining toolkit components confirmed.

```spl
index=main host=EC2AMAZ-SRGIV5B (EventCode=1 OR EventCode=3 OR EventCode=22)
  (Image="*anydesk*" OR Image="*AnyDesk*")
| eval info=case(
    EventCode=1, "EXEC: ".CommandLine,
    EventCode=3, "NET: ".DestinationIp.":".DestinationPort,
    EventCode=22, "DNS: ".QueryName)
| table _time EventCode Image info
| sort _time
```

---

### Slide 29 — AnyDesk: Alternative C2 Channel Established

No new query — this slide summarizes the AnyDesk evidence from Slide 28. Key findings:

- **EID 1:** `anydesk.exe --start` from `...\Downloads\APT33\vfs\`, ParentImage = a1.exe
- **EID 3:** Outbound to `143.244.61.217:443` and `186.233.187.24:443`
- **EID 22:** DNS queries to `relay-*.net.anydesk.com`

**Detection logic:** AnyDesk running from Downloads, launched by a C2 implant, is not a user installing remote support software. Context catches what signatures miss.

---

### Slide 30 — Hunt 4: AD Reconnaissance (EID 1 + EID 3)

**What it shows:** ADExplorer taking a full offline Active Directory snapshot via LDAP to the Domain Controller.

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode IN (1, 3, 22) Image="*ADExplorer*"
| table _time EventCode Image CommandLine DestinationIp DestinationPort QueryName
| sort _time
```

**Why this matters:** EID 1 shows `ADExplorer64.exe -snapshot "SCYTHE" domain_var_snapshot.dat`. EID 3 shows LDAP connection to `172.31.28.55:389` (the Domain Controller). The -snapshot flag = full offline AD copy: every user, every group, every GPO, every trust relationship.

---

### Slide 31 — Hunt 4: Lateral Movement (net use)

**What it shows:** net use with stolen credentials attempting to mount a share on a second endpoint.

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=1 Image="*net.exe"
| stats values(CommandLine) by Image ParentImage
```

More specific — look for UNC path patterns:

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=1
  CommandLine="*net use*\\\\*"
| table _time ParentImage Image CommandLine
| sort _time
```

**Why this matters:** The command line contains the plaintext password from LaZagne (`SecureP@ss11!!`) and the target hostname (`EC2-JFHQ02`). This is the pivot to a second host — scope expands here.

---

### Slide 32 — AD Recon & Lateral Movement Summary

No new query — this slide summarizes Slides 30 and 31. Key callout: finding ADExplorer targeting the Domain Controller is entity-based hunting in action. When an adversary touches your crown jewels (DCs, jump boxes, file servers), entity-based instincts should fire regardless of whether you started the hunt with CTI.

---

### Slide 33 — Hunt 5: Full Network Picture (EID 3 + EID 22 Stats)

**What it shows:** Every external communication from the endpoint, aggregated by process.

```spl
index=main host=EC2AMAZ-SRGIV5B
  (EventCode IN (3,22)) Image IN ("*\\a1.exe", "*\\anydesk.exe", "*\\adexplorer.exe")
| stats values(QueryName) as DNS values(DestinationIp) as IPs by Image
```

> **Tip:** If no results, check binary name casing. Try removing the Image filter first to see actual field values, then narrow.

---

### Slide 34 — The Full Network Picture (Summary Table)

No new query for this slide — it's a summary table built from the queries above. Use these for the full picture:

**All outbound connections:**

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=3
| eval ImageName=replace(Image,".*\\\\","")
| stats count dc(DestinationPort) as ports values(DestinationPort) as PortList
    by ImageName DestinationIp
| sort -count
```

**DNS queries:**

```spl
index=main host=EC2AMAZ-SRGIV5B EventCode=22
| eval ImageName=replace(Image,".*\\\\","")
| stats count by ImageName QueryName
| sort -count
```

**Complete network summary from the hunt:**

| Process | Destination | Port | Purpose |
|---------|-------------|------|---------|
| a1.exe | 13.58.116.24 | 443 | Primary C2 — all commands + exfil |
| AnyDesk.exe | 143.244.61.217 | 443 | AnyDesk relay — backup C2 |
| AnyDesk.exe | 186.233.187.24 | 443 | AnyDesk relay — redundant access |
| ADExplorer.exe | 172.31.28.55 | 389 | LDAP to Domain Controller |

**Key DNS queries:**

| Domain | Resolved by | Purpose |
|--------|-------------|---------|
| training.stage.unicorncroft.com | a1.exe | Primary C2 staging domain — IOC |
| relay-*.net.anydesk.com | AnyDesk.exe | AnyDesk relay infrastructure |
| EC2AMAZ-JFOCHEQ.scythe.lab | ADExplorer.exe | Domain Controller FQDN |
