# Threat Hunting Safari: An Intelligence-Driven Hunt for APT33

**BSides KC 2026** — Tyler Casey, [SCYTHE](https://scythe.io)

A 50-minute talk walking through a real, end-to-end threat hunt against APT33 (Peach Sandstorm) using actual telemetry from an adversary emulation of the Tickler malware campaign. Every query, every pivot, every finding comes from real Sysmon and Windows event data — not synthetic logs or hypotheticals.

---

## What This Talk Covers

Starting from a single line in Microsoft's August 2024 threat intelligence report, we hunt through Splunk telemetry and follow the evidence through 5 hunts and 12 pivots to reconstruct the full kill chain:

1. **CTI to Hypothesis** — Extracting huntable procedures from the Microsoft Peach Sandstorm report
2. **The Initial Hit** — Sigma rule match on a double-extension file (tickler.pdf.exe)
3. **Scoping the Endpoint** — EventCode breakdown to map all activity on the host
4. **Process Tree Analysis** — Discovering a1.exe (C2 implant) as root of all activity
5. **Discovery Cascade** — whoami, dir, net use, AV check, DNS, arp — what the adversary learned
6. **Tool Staging** — peaches.zip extracted to a full 10-piece operational toolkit
7. **Persistence** — tickler → sold.dll → SharePoint.bat → Registry Run key, with PowerShell EID 4103 proving sold.dll orchestration
8. **Credential Harvesting** — LaZagne + LSASS access with 0x1FFFFF (PROCESS_ALL_ACCESS), output staged for exfiltration
9. **RMM Deployment** — AnyDesk as backup/redundant C2 from non-standard path
10. **AD Reconnaissance** — ADExplorer -snapshot of the Domain Controller over LDAP (port 389)
11. **Lateral Movement** — net use with stolen credentials from LaZagne
12. **Network & Exfiltration** — Full C2, DNS, and data staging picture with IOC extraction

---

## Repo Structure

```
├── README.md                              # You are here
├── resources.md                           # References, tools, and further reading
├── splunk_queries_by_slide.md             # Every Splunk query used in the talk, by slide
├── talk_outline.md                        # Detailed talk outline with speaker notes
│
├── BSidesKC_ThreatHuntingSafari_v4.pptx  # The slide deck (39 slides)
│
├── sigma_rules/                           # 12 Sigma detection rules covering the full attack
│   ├── file_event_win_susp_double_extension.yml
│   ├── win_proc_creation_double_extension.yml
│   ├── proc_creation_win_susp_cmd_posh_parentimage.yml
│   ├── proc_creation_win_lolbas_discovery.yml
│   ├── proc_creation_win_sus_img_location.yml
│   ├── reg_set_win_run_keys.yml
│   ├── proc_creation_win_hktl_lazagne.yml
│   ├── proc_creation_win_remote_access_tools_anydesk.yml
│   ├── proc_creation_win_remote_access_tools_anydesk_susp_exec.yml
│   ├── proc_creation_win_RAS_nonstandard_folder.yml
│   ├── proc_creation_win_sysinternals_adexplorer_execution.yml
│   └── file_event_win_susp_archive_creation.yml
│
└── for_slides/
    ├── detection/
    │   ├── apt33_splunk.csv               # Raw Splunk telemetry export from the emulation
    │   └── images/                        # Splunk screenshots embedded in slides
    │
    ├── emulation/
    │   ├── APT-33 Update-emulation_outline.md    # SCYTHE emulation plan (automated + manual)
    │   ├── adversary-apt33-2025_SCYTHE_threat.json  # Importable SCYTHE threat package
    │   └── microsoft_cti_apt33.md         # Full text of Microsoft's Peach Sandstorm report
    │
    └── template/
        └── template_lockbit_hunt.md       # Workshop hunt template (LockBit scenario)
```

---

## Slide Deck Overview (39 Slides)

| Slides | Section | Content |
|--------|---------|---------|
| 1–2 | Opening | Title, whoami |
| 3 | Agenda | Five-part roadmap |
| 4–5 | Part 1 | Threat hunting methodologies; intelligence-based hunting scenario |
| 6 | Foundations | State-based changes — the breadcrumbs adversaries leave on endpoints |
| 7 | Part 3 | The hunt process (Hypothesis → Collect → Analyze → Investigate → Refine) |
| 8 | Part 2 | APT33 / Peach Sandstorm background — aliases, sectors, IRGC nexus |
| 9 | Part 2 | Tickler campaign details — procedures, tools, and timeline |
| 10 | Setup | Tooling & lab setup (Sysmon, Splunk, Sigma, SCYTHE) |
| 11 | Safari Start | The Safari Begins — transition slide |
| 12 | Safari Start | CTI → hypothesis — extracting tickler.pdf.exe as the hunt anchor |
| 13–14 | Initial Hit | Double-extension Sigma detection firing + what we found |
| 15–16 | Scoping | All-Sysmon EventCode breakdown — mapping the activity surface |
| 17–19 | Hunt 1 | Process tree (a1.exe as root), execution chain, discovery cascade |
| 20–21 | Hunt 2 | File creation (EID 11) — full adversary toolkit inventory |
| 22–24 | Hunt 3a | Persistence chain (EID 1 + EID 13 + PowerShell EID 4103) |
| 25–27 | Hunt 3b | Credential harvesting (LaZagne, LSASS 0x1FFFFF, staging for exfil) |
| 28–29 | Hunt 4a | AnyDesk — redundant C2 channel from non-standard path |
| 30–32 | Hunt 4b | AD recon (ADExplorer -snapshot), lateral movement (net use), analysis |
| 33–34 | Hunt 5 | Full network picture — C2, AnyDesk relays, LDAP to DC, DNS queries |
| 35 | Summary | Full kill chain reconstruction — 12 pivots mapped to ATT&CK |
| 36 | Detection | All 12 Sigma rules covering each phase of the attack |
| 37–38 | Takeaways | Six key lessons; three actionable next steps |
| 39 | Close | Thank you, contact info |

---

## How to Use These Resources

**If you attended the talk** — `splunk_queries_by_slide.md` has every query shown on screen, ready to copy-paste into your own Splunk instance. The Sigma rules in `sigma_rules/` can be translated to your SIEM using [sigma-cli](https://github.com/SigmaHQ/sigma-cli) or [Sigconverter.io](https://sigconverter.io/).

**If you want to replicate the hunt** — the SCYTHE threat package (`for_slides/emulation/adversary-apt33-2025_SCYTHE_threat.json`) can be imported into SCYTHE to generate the same telemetry in your own lab. The password for the zip is `r4inb0wUn1corn!`. The emulation outline covers every step — automated and manual — with module-level detail. The raw Splunk telemetry export from our emulation is in `for_slides/detection/apt33_splunk.csv` if you want to replay it without running the emulation yourself.

**If you want to build your own hunt** — `for_slides/template/template_lockbit_hunt.md` is a worked example hunt (LockBit scenario) you can use as a structural template. The methodology is the same regardless of threat actor: CTI → Hypothesis → Initial Hit → Scope the Host → Follow Every Spoke → Pivot → Repeat.

---

## Key Tools Used

| Tool | Purpose | Link |
|------|---------|------|
| Splunk | SIEM / log analysis | [splunk.com](https://www.splunk.com/) |
| Sysmon | Enhanced Windows endpoint logging | [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| Sigma | Open-source detection rules | [SigmaHQ](https://github.com/SigmaHQ/SigmaHQ) |
| SCYTHE | Adversary emulation platform | [scythe.io](https://scythe.io) |

---

## MITRE ATT&CK Coverage

This hunt maps to the following techniques (APT33 / [G0064](https://attack.mitre.org/groups/G0064/)):

| Phase | Techniques |
|-------|-----------|
| C2 Implant & Discovery | T1059, T1033, T1082, T1083, T1049, T1016, T1007, T1518.001 |
| Tool Staging | T1105, T1036.007 |
| Persistence | T1547.001 |
| Credential Access | T1003, T1555 |
| RMM & AD Recon | T1219, T1087.002 |
| Collection & Exfiltration | T1560.001, T1041 |

---

## About

**Tyler Casey** — Lead Detection Engineer & Deputy of SCYTHE Labs
- Bluesky: [@1qazCasey](https://bsky.app/profile/1qazcasey)
- LinkedIn: [/tyler-j-casey](https://linkedin.com/in/tyler-j-casey)

This talk demonstrates that you don't need a massive SOC to do effective threat hunting. You need curiosity, telemetry, and a process — follow the pivots and the kill chain reveals itself.

---

## License

The Sigma rules are sourced from [SigmaHQ](https://github.com/SigmaHQ/SigmaHQ) and authored by Tyler Casey / SCYTHE (rules marked `@1qazCasey`) or community contributors as noted in each rule file. They are subject to their original licensing. The SCYTHE threat package and emulation materials are provided for educational and defensive purposes. All other content in this repository is provided as-is for the security community.
