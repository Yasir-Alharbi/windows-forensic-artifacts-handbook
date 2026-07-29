# Chapter 4: Windows Event Logs

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why Windows records event logs and how channels organize events.
- Identify the investigative value of Security, System, Application, and operational logs.
- Interpret common event log fields without overstating their meaning.
- Correlate event logs with file system, execution, and user activity artifacts.
- Recognize limitations caused by audit policy, retention, log clearing, time handling, and missing telemetry.

## 2. Introduction

Windows Event Logs are a major source of operating system and application telemetry. They record security auditing events, service activity, application errors, PowerShell activity, remote access events, scheduled task activity, and many other system behaviors.

For investigators, event logs are often the backbone of intrusion reconstruction. They can help answer:

- Who logged on?
- From where?
- When did a service appear?
- Was a process creation event recorded?
- Was the Security log cleared?
- Did PowerShell execute suspicious commands?
- Did authentication failures precede successful access?

Event logs are powerful, but they are configuration-dependent. If the relevant audit policy was not enabled, the event may not exist. If log size was too small, older events may have rolled over. If an attacker cleared logs, local evidence may be incomplete.

## 3. Why Windows Created This Artifact

Windows records event logs so the operating system, administrators, applications, and security components can report meaningful activity. Events are written by providers into channels. Microsoft describes a channel as a destination that collects events.

Common channels include:

- Security
- System
- Application
- Setup
- Forwarded Events
- Applications and Services logs

Operational channels under Applications and Services logs are especially important for DFIR because they often record component-specific behavior, such as PowerShell, Task Scheduler, Remote Desktop Services, Windows Defender, and Sysmon if installed.

## 4. Why Investigators Care

Event logs can provide time, account, host, and activity context that file system artifacts usually cannot provide alone.

| Investigative Need | Event Log Contribution |
| --- | --- |
| Logon reconstruction | Security log events can record successful and failed logons. |
| Process visibility | Process creation auditing may record executable path and command line. |
| Service persistence | System and Security events may record service installation. |
| Lateral movement | Logon type, source address, workstation name, and account fields may support movement analysis. |
| Defense evasion | Log clearing and audit policy changes may be visible. |
| Script activity | PowerShell logs may record command and script content if configured. |
| Timeline building | Events provide timestamped anchors for correlation. |

Event logs often turn file system evidence into a more complete incident story.

## 5. Internal Structure

Only several concepts are necessary for practical investigation.

### Providers

Providers are Windows components, services, drivers, or applications that write events.

### Channels

Channels organize events. The classic Windows logs are Security, System, and Application. Many modern components write to Applications and Services logs.

### Event IDs

An Event ID identifies a specific event type within a provider. Event IDs are not globally meaningful without the provider and channel. The same numeric ID can mean different things for different providers.

### Event Fields

Events contain structured fields. Important fields commonly include:

- time created
- provider
- channel
- Event ID
- record number
- computer
- user or subject account
- target account
- logon ID
- process ID
- process path
- source network address
- status and substatus codes
- message text

The message text is useful for humans, but structured fields are better for reliable analysis.

## 6. Data Stored

The exact data depends on the provider and Event ID. Several common event categories are especially useful in incident response.

| Event Area | Examples | Investigative Value |
| --- | --- | --- |
| Successful logon | Security 4624 | Session creation, account, logon type, source details when available. |
| Failed logon | Security 4625 | Password spraying, brute force, stale credentials, attempted access. |
| Process creation | Security 4688 | Process path, parent process context, command line if enabled. |
| Log clearing | Security 1102 | Evidence that the Security audit log was cleared. |
| Service installation | System 7045, Security 4697 where available | Potential service-based persistence or administration. |
| PowerShell | PowerShell Operational logs | Command and script activity when logging is enabled. |
| Scheduled tasks | Task Scheduler Operational logs | Task registration, launch, and completion context. |
| Remote Desktop | TerminalServices logs | RDP connection and session activity. |

This chapter introduces event logs broadly. Later chapters will cover PowerShell, services, scheduled tasks, and RDP in more detail.

## 7. Acquisition Methods

Event logs are commonly acquired as `.evtx` files from:

```text
C:\Windows\System32\winevt\Logs\
```

Acquisition options include:

- full disk image
- triage collection of selected `.evtx` files
- Windows Event Forwarding (WEF)
- Security Information and Event Management (SIEM) export
- Endpoint Detection and Response (EDR) event export
- live PowerShell collection with `Get-WinEvent`

For forensic work, preserve original `.evtx` files when possible. SIEM events are useful, but they may be normalized, filtered, delayed, or incomplete compared with the endpoint source.

Document:

- hostname
- log files collected
- collection time in UTC
- tool and version
- whether logs came from disk, live query, WEF, SIEM, or EDR
- time zone context
- evidence hashes when possible

## 8. Interpretation

Event log interpretation requires knowing the provider, Event ID, audit policy, and field semantics.

Example observation:

```text
Security Event ID 4624
Logon Type: 3
Target Account: alex
Source Network Address: 10.10.4.25
Time: 2026-07-14 03:18:40 UTC
```

Reasonable inference:

- Windows recorded a successful network logon for account `alex` from `10.10.4.25` on the destination host.

Unsupported conclusion:

- "Alex was physically using the keyboard."

Logon Type 3 is network logon, not interactive console use. User intent and physical presence require other evidence.

Another example:

```text
Security Event ID 4688
New Process Name: C:\Users\alex\AppData\Local\Temp\winupdate.exe
Creator Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

Reasonable inference:

- If process creation auditing was enabled and the event is authentic, Windows recorded PowerShell creating `winupdate.exe`.

Unsupported conclusion:

- "The file is malware."

Malware classification requires hash reputation, static analysis, behavioral evidence, sandboxing, memory evidence, or threat intelligence.

## 9. Strengths

Windows Event Logs have major strengths:

- Provide account and session context.
- Record security-relevant actions when auditing is enabled.
- Support process, service, logon, and administrative activity reconstruction.
- Include structured fields useful for correlation.
- Can be centralized through WEF or SIEM.
- Often provide precise timestamps.
- Can reveal defense evasion such as Security log clearing.

Event logs are especially strong when combined with file system artifacts. File system metadata shows what changed; event logs can help identify who, from where, and sometimes through which process.

## 10. Weaknesses

Event logs also have significant weaknesses:

- Events depend on audit policy and provider configuration.
- Logs roll over when maximum size is reached.
- Local logs can be cleared.
- Some fields may be blank, unavailable, or misleading in certain logon types.
- Process command lines require explicit configuration for Security 4688.
- SIEM copies may be filtered or normalized.
- Time zone conversion errors can distort timelines.
- Event IDs must be interpreted with channel and provider context.

Do not treat missing events as proof that an action did not happen unless logging coverage is known and sufficient.

## 11. Common Mistakes

### Mistake 1: Reading Event IDs Without Provider Context

An Event ID alone is not enough. Always identify the channel and provider.

### Mistake 2: Treating Logon Type As User Intent

Logon type describes the kind of logon session Windows recorded. It does not prove whether the user was physically present, whether credentials were stolen, or whether the activity was automated.

### Mistake 3: Assuming 4688 Always Contains Command Line

Security 4688 records process creation when enabled. Command-line capture requires additional configuration. Absence of a command line may reflect configuration, not attacker stealth.

### Mistake 4: Ignoring Log Retention

If a log is too small, important events may roll over quickly. Always check log size, oldest record, newest record, and collection timing.

### Mistake 5: Overlooking Cleared Logs

Security Event ID 1102 indicates that the Security audit log was cleared. That event is a major investigative lead, but it still requires attribution and context.

## 12. Questions It Can Answer

Windows Event Logs can often help answer:

- Which account logged on to a host?
- What type of logon occurred?
- Were there failed logon attempts before access?
- Was process creation auditing enabled, and were suspicious processes recorded?
- Was a service installed?
- Was the Security log cleared?
- Did PowerShell, Task Scheduler, RDP, or another component record relevant activity?
- Does logged activity align with file system timestamps?

## 13. Questions It Cannot Answer

Event logs cannot answer by themselves:

- Whether a credential was stolen.
- Whether a logged-on user personally performed an action.
- Whether a binary is malicious.
- Whether missing activity never happened.
- Whether a SIEM has every original endpoint event.
- Whether a timestamp is reliable without time source and conversion review.

Event logs are evidence. They still need context.

## 14. Evidence Correlation

Event logs are one of the strongest correlation layers in Windows investigations.

| Correlating Artifact | Added Value |
| --- | --- |
| MFT | File existence, path, timestamps, and allocation state. |
| USN Change Journal | File creation, rename, write, and deletion activity. |
| `$LogFile` | Recent NTFS transaction support. |
| Prefetch | Execution evidence and run count context. |
| Amcache | Program inventory and execution-related leads. |
| Registry | Persistence configuration and system settings. |
| LNK / Jump Lists | User interaction with files. |
| Browser artifacts | Download and web activity context. |
| EDR telemetry | Process lineage, network activity, hash, and user session details. |

### Correlation Map

```text
Security 4624: network logon by account
        |
        +--> 4688 / EDR: process created during that session
        |
        +--> MFT / USN: file appeared shortly before process creation
        |
        +--> Prefetch / Amcache: execution-related evidence
        |
        +--> Network telemetry: outbound connection from process
        |
        +--> 1102 or audit changes: possible cleanup or evasion
```

## 15. Investigation Walkthrough

### Scenario

A server reports suspicious outbound connections. The suspected executable path is:

```text
C:\Users\alex\AppData\Local\Temp\winupdate.exe
```

### Step 1: Establish Access

Observation:

- Security 4624 records a network logon for account `alex` from `10.10.4.25`.
- Several Security 4625 failures for other accounts occurred from the same source before the successful logon.

Inference:

- The source host attempted authentication and then successfully authenticated as `alex`.
- The pattern may suggest credential guessing, stale credentials, or attacker activity. It is not conclusive by itself.

### Step 2: Identify Process Activity

Observation:

- Security 4688 records `powershell.exe` launching a process from the user's temporary directory.
- Command-line data is present and includes the suspicious path.

Inference:

- Windows recorded PowerShell creating the suspicious executable process.
- This supports execution attribution more strongly than MFT alone.

### Step 3: Check File System Evidence

Observation:

- MFT shows `winupdate.exe` created shortly before the process event.
- USN records show file create, data extend, close, and later delete activity.

Inference:

- File system artifacts support staging and cleanup around the process event.

### Step 4: Check Defense Evasion

Observation:

- Security 1102 appears after the suspicious process activity.

Inference:

- The Security audit log was cleared. Determine the account and logon ID associated with the event and correlate backward to logon events.

### Step 5: Write the Finding

Precise wording:

```text
Windows event logs show a successful network logon for account alex from 10.10.4.25 before suspicious process activity. Security 4688 records PowerShell launching C:\Users\alex\AppData\Local\Temp\winupdate.exe, and file system artifacts show the executable was created shortly before execution and deleted afterward. Security 1102 later records that the Security audit log was cleared. These findings support unauthorized remote activity if account ownership, source host context, and process lineage confirm the access was not legitimate administration.
```

## 16. ASCII Timeline

```text
03:16:02  4625: failed logon from 10.10.4.25
03:18:40  4624: successful network logon for alex from 10.10.4.25
03:22:11  MFT / USN: winupdate.exe created in Temp
03:23:02  4688: powershell.exe launches winupdate.exe
03:24:10  Network alert: outbound connection
03:25:40  USN: winupdate.exe deleted
03:30:05  1102: Security audit log cleared
```

The timeline supports investigation. It should be validated against source host evidence and centralized logs.

## 17. Investigator's Mindset

Treat event logs as structured testimony from Windows components. They are extremely useful, but they speak only when configured to speak and only within retained history.

Ask:

- Which channel and provider produced this event?
- Was the relevant audit policy enabled?
- What fields are direct values versus rendered message text?
- Is the event local, forwarded, or SIEM-normalized?
- What is the log retention window?
- Does the event prove the action, or only support a lead?
- What independent artifact can confirm the interpretation?

Good event log analysis is less about memorizing IDs and more about asking what Windows actually recorded.

## 18. Key Takeaways

- Windows Event Logs provide crucial account, session, process, service, and system activity context.
- Event IDs must be interpreted with channel and provider context.
- Audit policy and retention determine what evidence exists.
- Security 4624, 4625, 4688, 1102, System 7045, and related events are common investigative anchors.
- Process creation command lines require configuration.
- Local logs can roll over or be cleared.
- Strong conclusions come from correlating event logs with MFT, USN, `$LogFile`, execution artifacts, and endpoint telemetry.

## 19. Review Questions

1. Why is an Event ID alone insufficient for interpretation?
2. What does Security 4624 prove, and what does it not prove?
3. Why might Security 4688 lack command-line data?
4. Why is Security 1102 an important investigative lead?
5. How would you correlate event logs with MFT and USN evidence for a suspicious executable?

## 20. References

- Microsoft Learn, "Defining Channels": https://learn.microsoft.com/en-us/windows/win32/wes/defining-channels
- Microsoft Learn, "Event Viewer": https://learn.microsoft.com/en-us/shows/inside/event-viewer
- Microsoft Learn, "4624(S): An account was successfully logged on": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- Microsoft Learn, "4625(F): An account failed to log on": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
- Microsoft Learn, "4688(S): A new process has been created": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
- Microsoft Learn, "1102(S): The audit log was cleared": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
- Microsoft Learn, "Appendix L: Events to Monitor": https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
