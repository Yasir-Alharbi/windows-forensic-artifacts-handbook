# Chapter 24: End-to-End Investigation Walkthrough

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Apply artifact knowledge from the handbook to a complete Windows intrusion scenario.
- Build an evidence-backed timeline from browser, file system, execution, logon, persistence, Defender, PowerShell, and memory artifacts.
- Separate observation, evidence, inference, assumption, and conclusion in a final finding.
- Identify evidence gaps and determine what additional collection is needed.
- Produce a defensible incident reconstruction without overstating the artifacts.

## 2. Introduction

This chapter combines the handbook's artifacts into one practical investigation. The scenario is fictional, but the workflow is realistic.

The purpose is not to show every possible artifact. The purpose is to demonstrate how an investigator moves from alert to evidence, from evidence to timeline, and from timeline to careful conclusion.

The guiding rule remains:

**No single artifact tells the whole story. Strong findings come from correlation.**

## 3. Why Windows Created These Artifacts

The artifacts in this walkthrough were not created for one unified forensic purpose. Each exists because Windows or an application needed it:

- Browser history supports user browsing and download management.
- MFT and USN support NTFS file system operation.
- Prefetch supports application performance.
- Amcache supports application compatibility and inventory.
- Event Logs support auditing and troubleshooting.
- PowerShell logs support operational and security visibility.
- Scheduled Tasks, services, Run keys, and WMI support automation and system management.
- Defender logs support threat detection and remediation.
- Memory reflects runtime system state.

Incident reconstruction works because these independent systems record overlapping pieces of reality.

## 4. Why Investigators Care

End-to-end correlation helps answer the questions leadership, legal teams, and responders actually ask:

- How did the file arrive?
- Did it execute?
- What account was involved?
- What did it do?
- Did it persist?
- Did it move laterally?
- Was data staged or transferred?
- Was evidence removed or altered?
- What confidence do we have?
- What remains unknown?

The goal is a defensible explanation, not a dramatic story.

## 5. Internal Structure

This walkthrough follows a repeatable investigation structure.

| Phase | Purpose |
| --- | --- |
| Alert intake | Define the initial lead and scope. |
| Evidence preservation | Collect volatile and durable artifacts. |
| File origin | Determine how suspicious files arrived. |
| Execution | Test whether suspicious files or commands ran. |
| Persistence | Identify mechanisms that survive logon or reboot. |
| Lateral movement | Reconstruct account and host movement. |
| Defense evasion | Identify tampering, deletion, or log clearing. |
| Timeline | Place events in sequence. |
| Findings | State evidence-backed conclusions and gaps. |

## 6. Data Stored

The case uses these artifact categories:

| Artifact | Case Use |
| --- | --- |
| Browser History | Download URL and target path. |
| Zone.Identifier | Internet-origin context. |
| MFT | File existence, timestamps, deleted records. |
| USN Change Journal | File creation, write, rename, deletion sequence. |
| Prefetch | Execution-related evidence. |
| Amcache | Path, metadata, and hash context. |
| Event Logs | Logon, process, service, scheduled task, and log clearing events. |
| PowerShell logs | Script block and command content. |
| Scheduled Tasks | Persistence configuration. |
| Services | Lateral movement or privileged persistence evidence. |
| Defender logs | Detection, remediation, and configuration changes. |
| Memory | Runtime process and network corroboration. |
| Network logs | Destination and traffic context. |

## 7. Acquisition Methods

For this scenario, the recommended collection includes:

- full triage package from the affected workstation
- MFT, USN, and `$LogFile`
- Security, System, PowerShell, Defender, TaskScheduler, Terminal Services logs
- browser profiles
- user hives and SYSTEM/SOFTWARE hives
- Prefetch, Amcache, ShimCache
- Scheduled Task files and TaskCache Registry data
- memory capture if host is still live
- EDR timeline export
- proxy, DNS, firewall, VPN, and domain controller logs
- suspicious binaries, scripts, LNK files, and quarantine data

Document:

- collection time in UTC
- host isolation time
- tool names and versions
- evidence hashes
- collection gaps
- whether artifacts came from endpoint, SIEM, EDR, or forensic image

## 8. Interpretation

Interpret the case in layers.

### Initial Alert

Observation:

```text
EDR alert: suspicious outbound connection
Host: WKSTN-042
Process path: C:\Users\alex\Downloads\winupdate.exe
Time: 2026-07-14 03:24:10 UTC
Destination: 198.51.100.25:443
```

Initial inference:

- A suspicious process on WKSTN-042 may have made an outbound connection.
- The process path is suspicious because it uses a system-like name from a user Downloads directory.

Do not yet conclude malware, execution chain, or user intent.

## 9. Strengths

The end-to-end method has several strengths:

- Tests each claim with independent evidence.
- Prevents single-artifact overclaiming.
- Exposes gaps early.
- Produces report-ready findings.
- Supports containment and scoping.
- Helps prioritize additional collection.

The method is slower than quick triage, but it produces stronger conclusions.

## 10. Weaknesses

Limitations include:

- Requires broad collection.
- Some artifacts may be missing or overwritten.
- Enterprise telemetry may be delayed or normalized.
- Time zone and clock skew errors can distort sequence.
- Memory may no longer be available.
- Browser sync and remote access can complicate user attribution.
- Final conclusions may still include uncertainty.

Professional investigations do not eliminate uncertainty. They manage it honestly.

## 11. Common Mistakes

### Mistake 1: Starting With the Malware Label

Start with evidence. A detection name or suspicious filename is not the whole case.

### Mistake 2: Claiming User Intent Too Early

A browser profile, logon event, or user path does not prove the account owner acted intentionally.

### Mistake 3: Ignoring Benign Explanations

Administrative tools, updates, installers, and enterprise scripts can look suspicious. Test context.

### Mistake 4: Failing to Preserve Volatile Evidence

Memory, active connections, and EDR live state can disappear quickly.

### Mistake 5: Reporting Every Event Instead of the Key Chain

A report should include the evidence chain that supports findings, not every parsed row.

## 12. Questions It Can Answer

The walkthrough method can help answer:

- What was the first known suspicious activity?
- How did the suspicious file arrive?
- Did it execute?
- What account and session context existed?
- Was persistence configured?
- Was lateral movement attempted?
- Did security tooling detect or remediate anything?
- Was evidence deleted, altered, or cleared?
- What conclusions are high confidence?
- What remains unresolved?

## 13. Questions It Cannot Answer

Even an end-to-end workflow cannot answer by itself:

- The attacker's identity.
- Whether a user knowingly cooperated.
- Whether all compromised hosts were found without enterprise scoping.
- Whether all data exposure is known without content and network evidence.
- Whether missing evidence never existed.
- Whether every artifact is complete and untampered.

## 14. Evidence Correlation

The core correlation chain:

| Claim | Supporting Evidence |
| --- | --- |
| File downloaded | Browser download record, MFT/USN creation, Zone.Identifier. |
| File executed | EDR process event, Prefetch, Amcache. |
| PowerShell staging occurred | 4104 script block, 4688/EDR command line, MFT/USN script creation. |
| Persistence configured | Scheduled Task XML, TaskScheduler 106, Registry/TaskCache, EDR process. |
| Outbound connection occurred | EDR network event, firewall/proxy logs, SRUM. |
| Lateral movement occurred | 4624 Type 10/3, Terminal Services logs, service creation, source-host evidence. |
| Cleanup occurred | USN delete records, `$LogFile`, Event 1102, Defender tamper/configuration events. |

### Correlation Map

```text
Browser download
        |
        +--> MFT / USN file creation
        |
        +--> Defender detection
        |
        +--> Prefetch / EDR execution
        |
        +--> PowerShell staging
        |
        +--> Scheduled Task persistence
        |
        +--> Network activity
        |
        +--> RDP / service creation on another host
        |
        +--> Cleanup and evidence conflict
```

## 15. Investigation Walkthrough

### Step 1: Confirm File Origin

Observation:

- Edge History records a download of `winupdate.exe` from a suspicious URL.
- Target path is `C:\Users\alex\Downloads\winupdate.exe`.
- Zone.Identifier contains Internet zone and source URL context.
- MFT and USN show file creation during the download window.

Inference:

- The file likely arrived through browser download into Alex's Downloads folder.

### Step 2: Confirm Execution

Observation:

- EDR records process creation for `winupdate.exe`.
- Prefetch contains `WINUPDATE.EXE-...pf`.
- Amcache records metadata for the same path.

Inference:

- Execution is supported by independent process and execution-related artifacts.

### Step 3: Identify Parent Process and User Session

Observation:

- EDR shows `explorer.exe` launching `winupdate.exe`.
- Security 4624 shows Alex's interactive logon before execution.
- UserAssist or Jump Lists may show related shell activity.

Inference:

- Execution occurred within Alex's user session and appears shell-associated.
- This still does not prove Alex's intent.

### Step 4: Identify PowerShell Staging

Observation:

- After execution, EDR shows `winupdate.exe` launching PowerShell.
- PowerShell 4104 logs show download of `update.ps1` to `C:\Users\Public`.
- MFT and USN show `update.ps1` created shortly afterward.

Inference:

- The suspicious executable likely launched PowerShell to stage a script.

### Step 5: Identify Persistence

Observation:

- TaskScheduler Event 106 records a task named `UpdateCheck`.
- Task XML runs PowerShell with `C:\Users\Public\update.ps1`.
- TaskScheduler Event 200 later shows the action started.

Inference:

- A scheduled task was configured for persistence or recurring execution, and later execution is supported by task action evidence.

### Step 6: Identify Security Product Evidence

Observation:

- Defender Event 1116 detected `winupdate.exe`.
- Defender Event 1117 indicates an action was taken.
- Defender Event 5007 later records an exclusion change for `C:\Users\Public`.

Inference:

- Defender detected the suspicious file and recorded remediation activity.
- The exclusion change is suspicious and may indicate tampering if correlated with process or policy evidence.

### Step 7: Identify Lateral Movement

Observation:

- Security logs on FILESRV01 show 4624 Type 10 for `CORP\alex` from WKSTN-042.
- Terminal Services logs support an RDP session.
- System Event 7045 records a service installed on FILESRV01.
- The service binary path is `C:\Users\Public\winupdate.exe`.

Inference:

- Evidence supports RDP-based lateral movement from WKSTN-042 to FILESRV01 using Alex's account, followed by service creation.

### Step 8: Identify Cleanup and Conflict

Observation:

- USN records show deletion of `winupdate.exe` after execution.
- Security Event 1102 records audit log clearing on WKSTN-042.
- MFT timestamps on one staged file are older than USN creation records.

Inference:

- Evidence supports cleanup activity and possible timestomping or timestamp manipulation.
- Timestomping requires direct support from process telemetry, PowerShell logs, or stronger timestamp discrepancy analysis.

### Step 9: Build Final Timeline

```text
03:21:52  Browser: winupdate.exe download begins
03:22:05  MFT / USN: winupdate.exe created
03:22:07  Defender 1116: threat detected
03:23:02  Prefetch: WINUPDATE.EXE execution-related timestamp
03:23:04  EDR: winupdate.exe process starts
03:23:20  EDR: winupdate.exe launches powershell.exe
03:23:22  PowerShell 4104: update.ps1 download command
03:23:24  MFT / USN: update.ps1 created in C:\Users\Public
03:24:10  EDR / firewall: outbound connection to 198.51.100.25:443
03:26:04  TaskScheduler 106: UpdateCheck task registered
03:30:05  Security 1102: audit log cleared
03:41:33  FILESRV01 4624 Type 10: CORP\alex from WKSTN-042
03:45:12  FILESRV01 7045: suspicious service installed
```

### Step 10: Write Final Finding

Precise finding:

```text
WKSTN-042 contains correlated evidence that winupdate.exe was downloaded through Alex's Edge profile, written to C:\Users\alex\Downloads, detected by Defender, and executed shortly afterward. EDR and Prefetch support execution, while PowerShell logs and file system artifacts show subsequent staging of update.ps1 under C:\Users\Public. Scheduled Task artifacts show persistence configured to run the staged script. Later, FILESRV01 recorded RDP logon activity from WKSTN-042 using CORP\alex and service creation pointing to a suspicious binary. USN records and Event 1102 support cleanup and log-clearing activity. The evidence supports compromise of Alex's session or credentials; it does not by itself prove Alex's intent.
```

## 16. ASCII Timeline / Flow Diagram

```text
Internet URL
    |
    v
Browser download -> MFT/USN file creation -> Defender detection
    |
    v
Execution evidence: EDR + Prefetch + Amcache
    |
    v
PowerShell staging -> update.ps1 created
    |
    v
Scheduled Task persistence
    |
    v
Outbound network activity
    |
    v
RDP to FILESRV01 -> service creation
    |
    v
Cleanup: file deletion + log clearing
```

## 17. Investigator's Mindset

A mature investigation is not a list of artifacts. It is a tested explanation.

Ask:

- What is the earliest reliable suspicious event?
- Which claim has independent support?
- Which artifact could be misleading?
- What benign explanations were tested?
- What happened on the source host and destination host?
- What evidence supports execution, persistence, and movement?
- Where are the gaps?
- What can be said with high confidence?
- What must remain qualified?

The best findings are clear enough for responders and careful enough for peer review.

## 18. Key Takeaways

- End-to-end reconstruction depends on correlation across independent artifacts.
- File origin, execution, persistence, lateral movement, and cleanup should be proven separately.
- User-profile evidence does not prove user intent.
- Detection does not prove remediation; download does not prove execution; configuration does not prove successful launch.
- Evidence conflict should be investigated, not ignored.
- Final findings should state confidence and limitations.
- Professional-quality DFIR writing is evidence-first and inference-aware.

## 19. Review Questions

1. Which artifacts support file download origin?
2. Which artifacts support execution?
3. Why does user-session evidence not prove user intent?
4. What evidence supports scheduled task persistence?
5. How should cleanup and log clearing be included in a final finding?

## 20. References

- Microsoft Learn, "4624(S): An account was successfully logged on": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- Microsoft Learn, "4688(S): A new process has been created": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
- Microsoft Learn, "1102(S): The audit log was cleared": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
- Microsoft Learn, "Task Scheduler Schema": https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema
- Microsoft Learn, "Microsoft Defender Antivirus event IDs and error codes": https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
- Microsoft Learn, "[MS-SHLLINK]: Shell Link (.LNK) Binary File Format": https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/99ac930d-9419-4254-b6c9-0f909af95c13
- Plaso Documentation: https://plaso.readthedocs.io/
- MITRE ATT&CK, "Indicator Removal: Timestomp": https://attack.mitre.org/techniques/T1070/006/
