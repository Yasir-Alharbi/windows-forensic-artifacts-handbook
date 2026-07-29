# Chapter 21: Memory Forensics as Corroborating Evidence

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why memory evidence is volatile and valuable.
- Identify what memory analysis can add to Windows artifact correlation.
- Use memory evidence to corroborate process, network, injection, module, handle, and command-line findings.
- Understand common acquisition options and risks.
- Avoid overstating memory artifacts without disk, log, or network correlation.

## 2. Introduction

Memory forensics analyzes volatile system memory captured from a live or recently crashed system. Unlike disk artifacts, memory can contain active processes, command lines, network connections, loaded modules, injected code, decrypted configuration, credentials, registry hives, handles, and strings that may never be written to disk.

This handbook focuses on Windows forensic artifacts, so this chapter treats memory as corroborating evidence. Memory can answer questions that disk artifacts cannot, but it is also a snapshot. It shows what existed at capture time, plus recoverable remnants, not a complete history.

Memory is especially valuable when investigating:

- fileless malware
- process injection
- command-and-control activity
- credential theft tools
- suspicious PowerShell or .NET activity
- malware unpacking
- deleted or encrypted files
- active network connections

## 3. Why Windows Created This Artifact

Windows did not create memory as an artifact for investigators. Memory is where the operating system and programs execute. Processes, threads, modules, handles, network structures, kernel objects, and user-mode data must exist in memory for the system to operate.

Windows can also generate memory dumps for debugging and troubleshooting. Microsoft describes dump files as snapshots in time, and Task Manager can create live kernel memory dumps or process dumps without crashing the system.

Investigators use these snapshots because they capture runtime state that logs and disk files may miss.

## 4. Why Investigators Care

Memory evidence helps connect configured or historical artifacts to live behavior.

| Investigative Need | Memory Contribution |
| --- | --- |
| Process validation | Shows running or recently recoverable processes. |
| Network context | May show active or residual connections. |
| Injection detection | Can reveal suspicious executable memory regions. |
| Command line context | May recover command lines and environment. |
| Module analysis | Shows loaded DLLs and suspicious modules. |
| Handle analysis | Shows files, registry keys, mutexes, and objects used by processes. |
| Fileless activity | May reveal code or scripts not present on disk. |
| Malware configuration | Strings or memory regions may contain C2, keys, or settings. |

Memory often answers "what was actually running when we captured the host?"

## 5. Internal Structure

Practical memory analysis usually relies on forensic frameworks such as Volatility 3, Volatility 2, Rekall, commercial tools, or EDR memory capture capabilities.

Common analysis categories:

| Category | Practical Use |
| --- | --- |
| Process lists | Compare active, scanned, and tree views of processes. |
| Command lines | Recover process command-line arguments. |
| Network scans | Identify connections and listening sockets. |
| DLL/module listings | Review loaded modules and paths. |
| Handles | Identify open files, registry keys, mutexes, and objects. |
| VAD analysis | Inspect virtual address descriptors for memory regions. |
| Injection indicators | Find suspicious executable/private memory. |
| Registry hives | Recover in-memory Registry data. |
| Strings | Search for domains, IPs, paths, commands, and keys. |

Different tools use different plugins and assumptions. Cross-check suspicious findings when possible.

## 6. Data Stored

Memory analysis may expose:

- process names
- process IDs and parent process IDs
- create and exit times
- command lines
- loaded modules and DLL paths
- open handles
- active and residual network connections
- injected or suspicious memory regions
- process environment variables
- registry keys and values
- clipboard or console remnants
- strings, URLs, IP addresses, and file paths
- decrypted malware configuration
- credentials or secrets in sensitive cases

Handle secrets carefully. Memory may contain passwords, tokens, private keys, and personal data.

## 7. Acquisition Methods

Memory acquisition options include:

- full physical memory capture
- process-specific dump
- live kernel memory dump
- crash dump
- hibernation file analysis
- EDR memory collection
- hypervisor snapshot

Acquisition can change the system. The acquisition tool runs in memory, writes output, may load drivers, and may trigger security product events. Document everything.

Minimum documentation:

- host name
- acquisition time in UTC
- tool and version
- command line
- output path
- hash of memory image
- memory size
- whether pagefile and hibernation files were collected
- whether the system was live, suspended, or crashed
- known security product reactions

Do not write large memory captures to the suspect volume if avoidable.

## 8. Interpretation

Memory interpretation should be tied to capture time.

Example observation:

```text
Memory capture time: 2026-07-14 03:40:00 UTC
Process: powershell.exe
Parent: WmiPrvSE.exe
Command line: powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\update.ps1
Network connection: 10.10.4.50:49712 -> 198.51.100.25:443
```

Reasonable inference:

- At or near memory capture time, PowerShell was present with command-line context showing execution of `update.ps1`.
- Parent context suggests WMI-related launch.
- Network structures support an active or recent connection associated with the process, depending on tool output and OS support.

Unsupported conclusion:

- "This proves the entire intrusion timeline."

Memory is a snapshot. Use disk and log artifacts to reconstruct before and after.

## 9. Strengths

Memory forensics has several strengths:

- Captures runtime state.
- Can reveal fileless and injected code.
- Can show active network context.
- Can recover command lines and process relationships.
- Can expose decrypted configuration.
- Can validate whether suspicious processes are active.
- Can support malware analysis when files are packed or deleted.

Memory often preserves the attacker's active working state.

## 10. Weaknesses

Limitations include:

- Volatile and time-sensitive.
- Acquisition can alter evidence.
- A capture is a snapshot, not complete history.
- Tool output depends on OS support and symbols.
- Rootkits and anti-forensics may manipulate views.
- Large images can be slow to process.
- Sensitive data handling requirements are high.
- Cloud and EDR memory captures may be partial.

Memory is powerful, but it is not automatically more authoritative than disk or logs.

## 11. Common Mistakes

### Mistake 1: Treating Memory As Complete History

Memory primarily reflects capture-time state and recoverable remnants. It does not replace timelines.

### Mistake 2: Trusting One Process View

Compare active process listing, process scanning, process trees, handles, and EDR data when possible.

### Mistake 3: Ignoring Acquisition Impact

The acquisition tool changes memory and may create file system and event artifacts.

### Mistake 4: Treating Suspicious Memory As Malware Without Analysis

Executable private memory is a lead. Confirm with dump analysis, disassembly, strings, behavior, and correlation.

### Mistake 5: Mishandling Secrets

Memory can contain credentials and sensitive data. Control access and storage carefully.

## 12. Questions It Can Answer

Memory forensics can often help answer:

- What processes were running or recoverable at capture time?
- What command lines were present?
- What network connections were active or recoverable?
- Which DLLs or modules were loaded?
- Were there suspicious injected memory regions?
- Which files or registry keys did a process have open?
- Did memory contain strings, URLs, or configuration related to malware?

## 13. Questions It Cannot Answer

Memory cannot answer by itself:

- What happened before the captured state unless remnants remain.
- Whether a process ran hours earlier and exited cleanly.
- Whether a network connection transferred specific content.
- Whether suspicious code is malicious without analysis.
- Whether disk artifacts are false simply because memory lacks evidence.
- Whether all hidden activity was detected by one tool.

## 14. Evidence Correlation

Memory is strongest when used to corroborate disk, log, and network evidence.

| Correlating Artifact | Added Value |
| --- | --- |
| Event Logs 4688 / EDR | Process creation and parent context. |
| PowerShell logs | Script content and command history. |
| MFT / USN | Files referenced by processes. |
| Prefetch / Amcache | Execution-related and file metadata context. |
| Services / Tasks / WMI | Persistence mechanism that launched process. |
| Network logs | Destination, duration, and traffic volume. |
| Defender logs | Detection and remediation context. |
| Browser artifacts | Download origin for in-memory payload. |

### Correlation Map

```text
Memory: process and connection observed
        |
        +--> 4688 / EDR: creation time and parent process
        |
        +--> MFT / USN: referenced script or binary exists
        |
        +--> PowerShell logs: command content
        |
        +--> Persistence artifacts: why process launched
        |
        +--> Network logs: destination and traffic context
```

## 15. Investigation Walkthrough

### Scenario

An endpoint shows suspicious outbound traffic, but the executable was deleted before triage.

### Step 1: Acquire Memory Promptly

Observation:

- Memory was captured while the host was isolated but still powered on.

Inference:

- Capture may preserve active process and network state that disk artifacts no longer show.

### Step 2: Review Processes

Observation:

- A suspicious `powershell.exe` process is present with parent `WmiPrvSE.exe`.

Inference:

- The parent-child relationship supports a WMI-triggered PowerShell hypothesis.

### Step 3: Review Command Line and Network

Observation:

- Command line references `C:\Users\Public\update.ps1`.
- Network structures show a connection to an external IP.

Inference:

- Memory supports active or recent PowerShell behavior connected to the suspicious destination.

### Step 4: Correlate Disk and Logs

Observation:

- MFT and USN show `update.ps1` was created and later deleted.
- PowerShell 4104 logs show script content.
- WMI artifacts show a filter-consumer-binding launching the script.

Inference:

- Memory corroborates the WMI persistence and PowerShell execution chain.

### Step 5: Write the Finding

Precise wording:

```text
Memory captured at 2026-07-14 03:40 UTC shows powershell.exe with parent WmiPrvSE.exe and a command line referencing C:\Users\Public\update.ps1. Network structures associate the process with an external connection. MFT, USN, PowerShell logs, and WMI subscription artifacts support that the script was staged, executed, and launched through WMI persistence.
```

## 16. ASCII Timeline

```text
03:12:42  MFT / USN: update.ps1 created
03:14:20  WMI: subscription configured
03:30:00  EDR / 4688: WmiPrvSE launches powershell.exe
03:30:02  4104: script block logged
03:40:00  Memory: powershell.exe and connection observed
03:45:10  USN: update.ps1 deleted
```

## 17. Investigator's Mindset

Memory analysis is capture-time reasoning. It can confirm what was alive, loaded, connected, or injected, but it needs timelines to explain how the system arrived there.

Ask:

- When was memory captured?
- What changed because of acquisition?
- Is the process active, terminated, hidden, or scanned?
- Does command-line evidence match logs?
- Do network structures match firewall or EDR data?
- Do handles point to files or registry keys in other artifacts?
- Is suspicious memory dumped and analyzed safely?
- What disk evidence explains the memory state?

Use memory to test hypotheses, not to replace the investigation.

## 18. Key Takeaways

- Memory is volatile runtime evidence.
- It can reveal active processes, command lines, network connections, handles, modules, injected code, and strings.
- A memory capture is a snapshot, not complete history.
- Acquisition changes the system and must be documented.
- Memory is especially valuable for fileless malware, process injection, and active command-and-control.
- Strong findings correlate memory with event logs, file system artifacts, persistence mechanisms, EDR, and network telemetry.

## 19. Review Questions

1. Why is memory evidence time-sensitive?
2. What can memory show that disk artifacts may miss?
3. Why is a memory capture not a complete timeline?
4. Which artifacts would you use to corroborate a suspicious process found in memory?
5. Why must memory containing credentials be handled carefully?

## 20. References

- Microsoft Learn, "Task Manager live memory dump": https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/task-manager-live-dump
- Microsoft Learn, "Varieties of Kernel-Mode Dump Files": https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files
- Volatility Foundation, "Volatility 3 Documentation": https://volatility3.readthedocs.io/
- Volatility Foundation, "Command Reference": https://github.com/volatilityfoundation/volatility/wiki/command-reference
- Volatility Foundation, "Command Reference Mal": https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal
- Rekall Forensics, "Plugin Reference": https://rekall.readthedocs.io/en/latest/plugins.html
- Varonis, "How to Use Volatility for Memory Forensics and Analysis": https://www.varonis.com/blog/how-to-use-volatility
