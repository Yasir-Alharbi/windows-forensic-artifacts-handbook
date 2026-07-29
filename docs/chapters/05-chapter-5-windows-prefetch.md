# Chapter 5: Windows Prefetch

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why Windows creates Prefetch files.
- Describe the investigative value of `.pf` files.
- Interpret Prefetch evidence as execution-related evidence with appropriate limits.
- Correlate Prefetch with MFT, USN, Amcache, event logs, and endpoint telemetry.
- Avoid common mistakes involving run counts, timestamps, deleted executables, and disabled Prefetch behavior.

## 2. Introduction

Windows Prefetch is a performance feature that helps applications and operating system components load more efficiently. It can create `.pf` files under:

```text
C:\Windows\Prefetch\
```

For investigators, Prefetch is valuable because a Prefetch file can indicate that Windows observed an executable run. The filename usually includes the executable name and a hash-like value derived from path information. Parsed Prefetch data may include execution timestamps, run count, referenced files, volume information, and other metadata depending on Windows version and parser support.

Prefetch is one of the most useful execution artifacts on Windows workstations. It is less consistently useful on servers, systems where Prefetch is disabled, or systems where settings and storage behavior reduce Prefetch creation.

## 3. Why Windows Created This Artifact

Windows created Prefetch for performance, not forensics. The operating system observes application startup behavior and records information that can help future launches load faster.

Related Windows performance features have changed naming and behavior over time. SuperFetch became SysMain in later Windows versions. Investigators should verify system configuration before relying heavily on Prefetch absence.

The forensic benefit is incidental: when Windows creates or updates a Prefetch file, investigators may gain evidence that an executable ran and which files were referenced during startup.

## 4. Why Investigators Care

Prefetch helps answer one of the most important DFIR questions: **did this executable run on this host?**

| Investigative Need | Prefetch Contribution |
| --- | --- |
| Execution evidence | A `.pf` file can support that an executable ran. |
| First timeline anchor | Last run timestamps can place execution in time. |
| Frequency context | Run count can show repeated execution, with caveats. |
| Deleted program evidence | Prefetch may remain after the executable is deleted. |
| Path differentiation | Prefetch filename hash helps distinguish executables with the same name from different paths. |
| File access context | Referenced files can support startup behavior analysis. |
| Correlation | Supports or challenges event log and file system timelines. |

Prefetch is often the bridge between "the file existed" and "Windows likely executed it."

## 5. Internal Structure

Investigators do not need to memorize the binary format, but several concepts matter.

### Prefetch Filename

Prefetch files commonly follow a pattern similar to:

```text
EXECUTABLE.EXE-HASH.pf
```

The executable name is visible. The hash-like value helps distinguish different execution paths for files with the same name.

### Execution Metadata

Parsed Prefetch output may show:

- executable name
- Prefetch hash
- run count
- last execution time
- additional execution timestamps depending on Windows version
- volume information
- directories and files referenced during startup

### Referenced Files

Prefetch may list files accessed during application startup. These references can support context but should not be treated as proof that the user opened each file intentionally.

## 6. Data Stored

Parsed Prefetch records commonly include:

| Field | Investigative Use |
| --- | --- |
| Executable name | Identifies the program associated with the Prefetch file. |
| Prefetch file path | Shows the `.pf` artifact location. |
| Run count | Provides a lower-bound style indicator of observed launches. |
| Last run time | Places recent execution in time. |
| Additional run times | May provide prior execution anchors. |
| Volume serial / device data | Helps associate execution with a volume. |
| Referenced files | Supports startup context and dependency analysis. |

Windows version and configuration affect what is present. Parser output should be interpreted with the target operating system in mind.

## 7. Acquisition Methods

Prefetch acquisition is usually straightforward:

- collect `C:\Windows\Prefetch\*.pf`
- preserve original timestamps and file metadata
- parse with a forensic Prefetch parser
- export structured output for timeline analysis

Common acquisition contexts:

| Method | Use Case |
| --- | --- |
| Full disk image | Best forensic preservation. |
| Triage collection | Fast endpoint collection. |
| EDR file retrieval | Useful when immediate remote collection is needed. |
| Live response | Practical but must be documented carefully. |

Document:

- host name
- Windows version
- collection time in UTC
- Prefetch directory contents
- tool and parser version
- whether the system was live
- whether Prefetch/SysMain settings were checked

## 8. Interpretation

Prefetch interpretation should be precise.

Example observation:

```text
Prefetch file: WINUPDATE.EXE-A1B2C3D4.pf
Last run: 2026-07-14 03:23:02 UTC
Run count: 1
```

Reasonable inference:

- Windows created or updated a Prefetch artifact associated with `WINUPDATE.EXE`.
- This supports that the executable ran on the host around the recorded time.

Unsupported conclusion:

- "The user intentionally launched malware."

Prefetch does not identify user intent. It also does not classify the file as malicious.

### Absence of Prefetch

No Prefetch file does not prove no execution occurred. Reasons include:

- Prefetch disabled or limited.
- Server operating system behavior or configuration.
- File executed too recently or under conditions that did not produce a `.pf`.
- Prefetch file deleted.
- Artifact not collected.
- Parser did not support that Windows version.

Absence is a lead about collection and configuration, not a final conclusion.

## 9. Strengths

Prefetch has several strengths:

- Strong execution-related artifact on many Windows workstations.
- May remain after the executable is deleted.
- Provides execution timing.
- Helps distinguish same-named executables from different paths.
- Provides run count context.
- Can expose suspicious execution from temporary, downloads, or user profile paths.
- Useful in timeline correlation.

Prefetch often provides quick value during triage because suspicious `.pf` filenames stand out.

## 10. Weaknesses

Prefetch has important weaknesses:

- May be disabled or reduced by configuration.
- Behavior varies by Windows version and system role.
- It does not prove user intent.
- It does not directly show process parent, command line, or network behavior.
- Run count and timestamp arrays require version-aware interpretation.
- Prefetch files can be deleted.
- Referenced files can be misunderstood.

Prefetch is execution-related evidence, not a complete process telemetry record.

## 11. Common Mistakes

### Mistake 1: Saying Prefetch Proves Malware

Prefetch can support execution. It does not determine whether a file is malicious.

### Mistake 2: Treating Absence As No Execution

No `.pf` file does not prove the program did not run. Always check system settings, collection scope, operating system type, and alternative execution artifacts.

### Mistake 3: Overstating Run Count

Run count is useful, but it should be treated with care. Windows version behavior, maintenance, and parser interpretation can affect what the investigator sees.

### Mistake 4: Assuming Referenced Files Were Opened By the User

Referenced files may be loaded during program startup. They are context, not direct proof of user-opened documents.

### Mistake 5: Ignoring Same-Named Executables

`setup.exe`, `svchost.exe`, and `update.exe` can exist in many paths. Use Prefetch hash, MFT data, Amcache, event logs, and EDR telemetry to identify the actual path.

## 12. Questions It Can Answer

Prefetch can often help answer:

- Did Windows record execution-related evidence for this executable?
- When did it last run?
- Are there prior recorded run times?
- How many observed runs are represented by the run count?
- Did an executable run from a suspicious directory?
- Does execution timing align with file creation and network activity?

## 13. Questions It Cannot Answer

Prefetch cannot answer by itself:

- Which user intentionally launched the program.
- What command line was used.
- Which parent process launched it.
- Whether the file was malicious.
- Whether no Prefetch means no execution.
- Whether referenced files were opened intentionally.
- Whether the executable connected to the network.

## 14. Evidence Correlation

Prefetch is strongest when correlated with file system and process evidence.

| Correlating Artifact | Added Value |
| --- | --- |
| MFT | File existence, path, timestamps, deleted-record evidence. |
| USN Change Journal | File creation, write, rename, and deletion sequence. |
| Event Logs 4688 | Process creation, parent process, command line if enabled. |
| Amcache | Program inventory and path/hash context. |
| ShimCache/AppCompatCache | Additional execution-related or presence leads. |
| SRUM | Application network/resource usage context. |
| EDR telemetry | Process lineage, user, hash, command line, network connections. |
| Browser artifacts | Download origin. |

### Correlation Map

```text
Prefetch: WINUPDATE.EXE ran at 03:23
        |
        +--> MFT: file created in Temp at 03:22
        |
        +--> USN: file written and later deleted
        |
        +--> 4688 / EDR: parent process and command line
        |
        +--> Browser / PowerShell: origin or staging mechanism
        |
        +--> Network telemetry: outbound connection after execution
```

## 15. Investigation Walkthrough

### Scenario

An analyst finds a deleted MFT record for:

```text
C:\Users\alex\AppData\Local\Temp\winupdate.exe
```

### Step 1: Search Prefetch

Observation:

- `WINUPDATE.EXE-A1B2C3D4.pf` exists in `C:\Windows\Prefetch`.
- Parsed output shows last run at `2026-07-14 03:23:02 UTC`.

Inference:

- Prefetch supports execution-related activity for `WINUPDATE.EXE` around that time.

### Step 2: Resolve Path Ambiguity

Observation:

- Amcache shows a path matching the temporary directory.
- MFT and USN show the file was created shortly before the Prefetch last run time.

Inference:

- The Prefetch artifact likely relates to the suspicious temporary-path executable, not a benign same-named file elsewhere.

### Step 3: Identify Process Lineage

Observation:

- Security 4688 or EDR telemetry shows PowerShell launching the file.

Inference:

- Process telemetry supports the execution chain and gives parent process context.

### Step 4: Determine Origin

Observation:

- Browser history, PowerShell logs, or EDR file-write telemetry may show how the file arrived.

Inference:

- Origin remains unproven until one of those sources supports it.

### Step 5: Write the Finding

Precise wording:

```text
Prefetch contains execution-related evidence for WINUPDATE.EXE with a last run time of 2026-07-14 03:23:02 UTC. MFT and USN records show a matching executable was created in C:\Users\alex\AppData\Local\Temp shortly before that time and deleted afterward. Event log or EDR process telemetry is required to identify the parent process, command line, and user session with higher confidence.
```

## 16. ASCII Timeline

```text
03:22:11  MFT / USN: winupdate.exe created in Temp
03:23:02  Prefetch: WINUPDATE.EXE execution-related timestamp
03:23:03  4688 / EDR: process creation if available
03:24:10  Network alert: outbound connection
03:25:40  USN: winupdate.exe deleted
```

## 17. Investigator's Mindset

Use Prefetch as strong execution-related evidence when present, but do not let one artifact carry the entire conclusion.

Ask:

- Is Prefetch enabled or expected on this system?
- Does the `.pf` filename map clearly to the suspicious executable?
- Are there same-named executables elsewhere?
- Does MFT or Amcache support the path?
- Does event or EDR telemetry show parent process and command line?
- Does the run time align with alerts, network activity, or user logon?
- Could normal administration explain the execution?

Prefetch is a powerful lead. Correlation turns it into a finding.

## 18. Key Takeaways

- Prefetch is a Windows performance feature with forensic value.
- A Prefetch file can support that Windows observed executable activity.
- Prefetch does not prove user intent, command line, parent process, or maliciousness.
- Absence of Prefetch does not prove absence of execution.
- Run counts and execution timestamps require Windows-version-aware interpretation.
- Prefetch is strongest when correlated with MFT, USN, Amcache, event logs, and EDR telemetry.

## 19. Review Questions

1. Why does Windows create Prefetch files?
2. What does Prefetch evidence support, and what does it not prove?
3. Why is Prefetch absence weak evidence?
4. How can same-named executables complicate Prefetch interpretation?
5. Which artifacts would you use to identify the parent process of a Prefetch-observed executable?

## 20. References

- Microsoft Learn, "SuperFetch(SysMain) service spikes the CPU": https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/superfetch-sysmain-service-spikes-cpu
- Microsoft Learn, "prefetch" Windows Performance Toolkit action: https://learn.microsoft.com/en-us/windows-hardware/test/wpt/prefetch
- Eric Zimmerman, "PECmd": https://github.com/EricZimmerman/PECmd
- Prefetch Parser, "SuperFetch, SysMain, and the Win10/11 Prefetch confusion": https://www.prefetchparser.com/en/blog/superfetch-sysmain-prefetch-confusion
