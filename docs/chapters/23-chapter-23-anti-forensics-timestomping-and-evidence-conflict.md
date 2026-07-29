# Chapter 23: Anti-Forensics, Timestomping, and Evidence Conflict

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain common Windows anti-forensic behaviors such as timestomping, log clearing, file deletion, and security tool tampering.
- Distinguish normal artifact conflict from malicious manipulation.
- Investigate timestamp discrepancies using MFT, USN, `$LogFile`, Prefetch, Amcache, and Event Logs.
- Interpret log clearing and missing evidence carefully.
- Write findings that acknowledge uncertainty without weakening valid conclusions.

## 2. Introduction

Real investigations are messy. Artifacts conflict. Logs are missing. Timestamps disagree. Files are deleted. Security tools detect something but do not retain the sample. Attackers may intentionally modify or remove evidence, but normal Windows behavior can also create confusing patterns.

Anti-forensics is the deliberate attempt to destroy, alter, hide, or mislead forensic evidence. Common Windows examples include:

- timestomping files
- clearing event logs
- deleting tools and scripts
- disabling security products
- adding antivirus exclusions
- wiping PowerShell history or logs
- using fileless execution
- renaming tools to blend in
- modifying audit policy

The investigator's job is not to assume tampering whenever evidence is inconvenient. The job is to test conflict.

## 3. Why Windows Created This Artifact

Windows did not create anti-forensics. Windows created administrative features that can be used legitimately or abused maliciously.

Examples:

- `wevtutil` can query, export, archive, and clear event logs.
- File timestamp APIs support legitimate file operations, copying, restoration, and synchronization.
- Security product exclusions support operational needs.
- Event log size and retention settings support storage management.

Attackers abuse legitimate capabilities to reduce visibility. Investigators must separate legitimate administration from defense evasion.

## 4. Why Investigators Care

Anti-forensics affects confidence and scope.

| Investigative Need | Anti-Forensics Impact |
| --- | --- |
| Timeline accuracy | Timestomping can mislead file sequence analysis. |
| Log review | Cleared or rolled logs can hide activity. |
| Malware recovery | Deleted or quarantined files may be unavailable. |
| Execution analysis | Fileless activity may leave few disk artifacts. |
| Attribution | Missing process logs can weaken creator-process claims. |
| Scope | Tampered hosts may require broader enterprise data. |
| Reporting | Findings must explain evidence gaps and conflict. |

Evidence conflict is not failure. It is an investigative signal.

## 5. Internal Structure

Think of anti-forensics in categories.

| Category | Examples | Investigative Response |
| --- | --- | --- |
| Timestamp manipulation | Timestomping, copy/restore effects | Compare `$STANDARD_INFORMATION`, `$FILE_NAME`, USN, Prefetch, Amcache, logs. |
| Log manipulation | Clearing Security log, deleting logs | Look for 1102, `wevtutil`, SIEM/WEF copies, EDR telemetry. |
| File removal | Tool deletion, script cleanup | Use USN, `$LogFile`, MFT deleted records, EDR, memory. |
| Security tool tampering | Disable protection, exclusions | Review Defender 5007, policy, PowerShell, EDR. |
| Execution hiding | Fileless, injection, LOLBins | Use memory, PowerShell logs, EDR, network logs. |
| Naming deception | Fake Windows names, trusted paths | Validate path, signer, hash, parent process, file metadata. |

## 6. Data Stored

Anti-forensics evidence may appear as:

- Security Event 1102 indicating the audit log was cleared
- `wevtutil` process creation or command-line evidence
- Defender Event 5007 configuration changes
- PowerShell logs showing `Set-MpPreference`, `wevtutil`, or timestamp APIs
- MFT timestamp discrepancies
- `$STANDARD_INFORMATION` and `$FILE_NAME` timestamp mismatch
- USN records contradicting MFT apparent time
- `$LogFile` transaction remnants
- deleted file records
- missing event ranges
- EDR records of file deletion or tampering
- memory evidence of fileless execution

No single artifact proves anti-forensics in every case. Look for patterns.

## 7. Acquisition Methods

Anti-forensics investigations require broader collection than normal triage.

Collect:

- MFT, USN, `$LogFile`
- Security, System, PowerShell, Defender, TaskScheduler, Terminal Services logs
- EDR timeline and raw telemetry
- WEF/SIEM copies
- memory if the system is still live
- Registry hives and transaction logs
- Prefetch, Amcache, ShimCache
- browser and download artifacts
- backups, Volume Shadow Copies, and snapshots if available

Document:

- evidence gaps
- log retention settings
- oldest and newest log record
- collection time in UTC
- system clock status if known
- any known administrative maintenance
- tools used for acquisition

## 8. Interpretation

Interpret conflict as a question.

Example observation:

```text
MFT Created:      2026-01-10 12:00:00 UTC
MFT Modified:     2026-01-10 12:00:00 UTC
USN File Create:  2026-07-14 03:22:11 UTC
Prefetch Run:     2026-07-14 03:23:02 UTC
```

Reasonable inference:

- The MFT timestamps appear inconsistent with USN and Prefetch timing.
- Possible explanations include timestomping, file copy preserving timestamps, archive extraction, restore operation, or parser/time conversion issue.

Unsupported conclusion:

- "The attacker timestomped the file."

That conclusion requires more evidence, such as process telemetry showing timestamp modification, PowerShell commands, suspicious `$SI`/`$FN` mismatch, or a pattern across attacker files.

## 9. Strengths

Anti-forensics analysis has several strengths:

- Reveals attacker cleanup and evasion behavior.
- Helps explain missing or conflicting evidence.
- Strengthens timelines by testing timestamp reliability.
- Identifies additional evidence sources such as SIEM or memory.
- Supports defense evasion findings.
- Helps avoid false confidence.

Properly handled conflict can make a report stronger, not weaker.

## 10. Weaknesses

Limitations include:

- Normal system behavior can look suspicious.
- Missing logs may be rollover, not clearing.
- Timestamp differences can be legitimate.
- Some tampering leaves little evidence.
- Tool and parser errors can create false conflict.
- EDR and SIEM data may be normalized or incomplete.
- Anti-forensics conclusions often require higher evidence standards.

Avoid turning every anomaly into an attacker action.

## 11. Common Mistakes

### Mistake 1: Assuming Every Timestamp Conflict Is Timestomping

Copying, extraction, backup restore, installation, synchronization, and parser issues can create timestamp surprises.

### Mistake 2: Treating Missing Logs As Cleared Logs

Logs can roll over. Check log size, retention, oldest record, and Event 1102 where applicable.

### Mistake 3: Ignoring Legitimate Administration

Administrators clear logs, add exclusions, and change policies. The question is whether the action is expected, authorized, and correlated.

### Mistake 4: Ignoring Centralized Logs

Local logs may be gone while WEF, SIEM, EDR, or domain controller logs preserve evidence.

### Mistake 5: Overwriting the Conflict With a Clean Story

If artifacts disagree, report the conflict and the confidence level. Do not hide uncertainty.

## 12. Questions It Can Answer

Anti-forensics analysis can often help answer:

- Were event logs cleared?
- Were security settings changed?
- Were suspicious files deleted after execution?
- Do file timestamps conflict with other evidence?
- Is there a plausible benign explanation?
- Which artifacts survived tampering?
- What confidence level is justified?

## 13. Questions It Cannot Answer

Anti-forensics analysis cannot answer by itself:

- Who performed the tampering without attribution evidence.
- Whether every missing artifact was intentionally removed.
- Whether a timestamp discrepancy is malicious in isolation.
- Whether no evidence means no activity.
- Whether cleanup fully succeeded.

## 14. Evidence Correlation

Anti-forensics cases require independent evidence.

| Suspicion | Correlation Pattern |
| --- | --- |
| Timestomping | MFT `$SI`/`$FN` disagreement + USN timing + process telemetry or command evidence. |
| Log clearing | Security 1102 + `wevtutil`/Event Viewer process + SIEM gap + account/session context. |
| Defender tampering | Event 5007 + PowerShell/EDR command + policy comparison. |
| Tool deletion | USN delete + `$LogFile` support + Prefetch/Amcache execution evidence. |
| Fileless execution | PowerShell/WMI/process telemetry + memory evidence + network logs. |

### Correlation Map

```text
Artifact conflict
        |
        +--> Normal explanation tested
        |
        +--> Independent artifact support
        |
        +--> Attribution evidence
        |
        +--> Confidence level
        |
        +--> Finding or unresolved conflict
```

## 15. Investigation Walkthrough

### Scenario

A suspicious executable appears to have a creation timestamp from six months before the incident, but EDR shows it executed during the incident.

### Step 1: Compare File System Timestamps

Observation:

- `$STANDARD_INFORMATION` timestamps are old.
- `$FILE_NAME` timestamps differ.

Inference:

- Timestamp disagreement exists and requires explanation.

### Step 2: Review USN

Observation:

- USN records show file creation and data write during the incident window.

Inference:

- NTFS recorded recent file activity despite old MFT-visible timestamps.

### Step 3: Check Execution Evidence

Observation:

- Prefetch and EDR show execution shortly after USN creation records.

Inference:

- Execution occurred during the incident window, regardless of old file timestamps.

### Step 4: Search for Manipulation Evidence

Observation:

- PowerShell logs show a command invoking timestamp modification against the file.

Inference:

- Timestomping is now strongly supported.

### Step 5: Write the Finding

Precise wording:

```text
The suspicious executable has old MFT-visible timestamps, but USN records show recent creation and write activity during the incident window. Prefetch and EDR telemetry support execution shortly afterward. PowerShell logs show timestamp modification against the file, supporting a timestomping conclusion. The timeline should use USN, process telemetry, and PowerShell evidence rather than relying on the altered MFT timestamps alone.
```

## 16. ASCII Timeline

```text
2026-01-10 12:00:00  MFT visible timestamps on suspicious file
2026-07-14 03:22:11  USN: file create / data write
2026-07-14 03:22:40  PowerShell: timestamp modification command
2026-07-14 03:23:02  Prefetch: execution-related timestamp
2026-07-14 03:23:04  EDR: process creation
2026-07-14 03:30:05  Security 1102: audit log cleared if present
```

## 17. Investigator's Mindset

Conflict is evidence. It tells you where to look next.

Ask:

- What exactly conflicts?
- Could normal Windows behavior explain it?
- Could parser or time-zone handling explain it?
- What independent artifact supports each side?
- Is there direct evidence of manipulation?
- What evidence survived outside the host?
- How should confidence be stated?

Do not rush from anomaly to accusation. Build the bridge.

## 18. Key Takeaways

- Anti-forensics includes timestomping, log clearing, file deletion, security tool tampering, and hidden execution.
- Artifact conflict is an investigative lead, not automatic proof of attacker manipulation.
- Timestomping requires correlation; timestamp mismatch alone is not enough.
- Log clearing should be tested with Event 1102, process telemetry, and centralized logs.
- Missing evidence may reflect rollover, configuration, or collection gaps.
- Strong findings explain uncertainty and preserve confidence levels.

## 19. Review Questions

1. Why does timestamp disagreement not automatically prove timestomping?
2. What artifacts help test a timestomping hypothesis?
3. What evidence supports Windows event log clearing?
4. Why are centralized logs important in anti-forensics investigations?
5. How should an investigator report unresolved artifact conflict?

## 20. References

- MITRE ATT&CK, "Indicator Removal: Timestomp": https://attack.mitre.org/techniques/T1070/006/
- MITRE ATT&CK, "Indicator Removal on Host": https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK, "Disable or Modify Tools: Clear Windows Event Logs": https://attack.mitre.org/techniques/T1685/005/
- MITRE ATT&CK Detection Strategy, "Cross-Platform Behavioral Detection of File Timestomping via Metadata Tampering": https://attack.mitre.org/detectionstrategies/DET0591/
- Microsoft Learn, "wevtutil": https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
- Microsoft Learn, "1102(S): The audit log was cleared": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
- Elastic, "Clearing Windows Event Logs": https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/defense_evasion_clearing_windows_event_logs
