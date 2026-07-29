# Chapter 7: ShimCache / AppCompatCache

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain the purpose of the Application Compatibility Cache (AppCompatCache), commonly called ShimCache.
- Locate the registry hive data that stores ShimCache entries.
- Interpret ShimCache as application compatibility evidence with version-specific limits.
- Correlate ShimCache with Amcache, Prefetch, MFT, USN, and event logs.
- Avoid overstating execution, ordering, and timestamp conclusions.

## 2. Introduction

ShimCache, also called AppCompatCache, is a Windows application compatibility artifact. It records information about executable files that Windows application compatibility components have observed.

For investigators, ShimCache can provide useful evidence of program presence and, in some Windows versions and circumstances, execution-related activity. It is particularly useful when suspicious files were deleted or when other execution artifacts are missing.

ShimCache is also one of the easiest Windows artifacts to overstate. It should not be treated as a simple list of programs run by a user. Its behavior varies by Windows version, system state, parser support, and shutdown behavior.

## 3. Why Windows Created This Artifact

Windows uses application compatibility infrastructure to help programs run correctly across operating system versions. Compatibility shims can adjust program behavior when needed.

ShimCache exists as part of that compatibility ecosystem. Windows records information that helps it evaluate executables and compatibility behavior. The forensic value is incidental.

Investigators benefit because these entries can preserve paths and file metadata for executables that may no longer exist on disk.

## 4. Why Investigators Care

ShimCache helps investigators find executable presence and possible execution leads.

| Investigative Need | ShimCache Contribution |
| --- | --- |
| Suspicious executable discovery | May show paths to executables observed by Windows. |
| Deleted tool leads | May preserve entries after files are removed. |
| External path leads | May include executables from removable or network paths. |
| Application compatibility context | Shows Windows compatibility subsystem interaction. |
| Correlation support | Can support Amcache, Prefetch, and event log evidence. |
| Triage | Quickly surfaces unusual paths and filenames. |

ShimCache is strongest when it helps identify suspicious paths that deserve deeper correlation.

## 5. Internal Structure

ShimCache data is stored in the SYSTEM registry hive. Common locations include paths under:

```text
SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

Historical Windows versions may use different paths or structures. Parser support matters.

Common parsed fields may include:

- path
- file size
- last modified time
- cache entry metadata
- execution flag or indicator in some parser and Windows-version combinations

The presence and meaning of execution-related indicators are version-specific. Always consult parser documentation and validate with other artifacts.

## 6. Data Stored

Parsed ShimCache output commonly includes:

| Field | Investigative Use |
| --- | --- |
| Path | Identifies executable location. |
| Last modified time | File metadata timestamp, not execution time. |
| File size | Supports file identity comparison. |
| Entry order | May provide limited ordering clues, depending on Windows version. |
| Execution indicator | May exist in some versions and parsers; requires caution. |

The most important warning: **ShimCache timestamps are not generally execution timestamps.** They often represent file modification metadata.

## 7. Acquisition Methods

Acquire the SYSTEM hive and transaction logs when possible:

```text
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SYSTEM.LOG1
C:\Windows\System32\config\SYSTEM.LOG2
```

Acquisition options include:

- full disk image
- registry hive extraction from forensic image
- triage collection
- endpoint response retrieval
- live collection with tools that handle locked hives

Document:

- host name
- Windows version
- acquisition time in UTC
- whether the system was live or offline
- parser and version
- SYSTEM hive path and hash
- whether transaction logs were collected

## 8. Interpretation

ShimCache interpretation should be cautious and version-aware.

Example observation:

```text
ShimCache entry:
Path: C:\Users\alex\AppData\Local\Temp\winupdate.exe
Last modified: 2026-07-14 03:21:58 UTC
```

Reasonable inference:

- Windows application compatibility data contains an entry for the executable path.
- The path is suspicious and supports further investigation.
- The last modified timestamp may help compare the entry to MFT and Amcache data.

Unsupported conclusion:

- "The file executed at 03:21:58 UTC."

That timestamp is not automatically an execution time. Execution requires stronger supporting evidence.

## 9. Strengths

ShimCache has several strengths:

- Can preserve paths to executables after deletion.
- Useful for identifying suspicious file locations.
- May include executables from removable or network paths.
- Provides supporting evidence when Prefetch is absent.
- Helps compare program presence with Amcache and MFT.
- Useful in triage because unusual paths stand out quickly.

ShimCache is often valuable as a lead generator.

## 10. Weaknesses

ShimCache limitations are substantial:

- It is not a complete execution log.
- Behavior differs across Windows versions.
- Entries may not be written to disk until shutdown or other system activity.
- Timestamps are commonly file modification times, not execution times.
- Ordering interpretation can be unreliable.
- Execution indicators require parser- and version-specific validation.
- It does not provide user, parent process, command line, or network context.

Do not make ShimCache carry a conclusion that belongs to process telemetry or multiple correlated artifacts.

## 11. Common Mistakes

### Mistake 1: Treating Last Modified Time As Execution Time

This is the classic ShimCache mistake. Last modified time usually reflects file metadata, not when the executable ran.

### Mistake 2: Claiming Execution From Presence Alone

An entry may indicate Windows observed or cached information about an executable. Execution interpretation depends on operating system version, parser support, and corroboration.

### Mistake 3: Ignoring Shutdown Behavior

Some ShimCache data may be written to disk during shutdown. A live system may contain relevant information in memory that is not yet reflected in the hive.

### Mistake 4: Comparing Entries Across Windows Versions As If They Behave Identically

ShimCache structure and meaning changed over time. Version context is mandatory.

### Mistake 5: Forgetting Same-Named Executables

Resolve suspicious entries by full path and supporting artifacts. Do not assume a filename alone identifies the file.

## 12. Questions It Can Answer

ShimCache can often help answer:

- Did Windows record an application compatibility entry for this executable path?
- Was a suspicious executable path present in compatibility data?
- Does the entry support the existence of a deleted or missing executable?
- Does the path align with Amcache, Prefetch, MFT, or event log evidence?
- Are there suspicious executables in user-writable, removable, or network locations?

## 13. Questions It Cannot Answer

ShimCache cannot answer by itself:

- Whether the file conclusively executed.
- Exactly when the file executed.
- Which user ran the file.
- What parent process launched the file.
- What command line was used.
- Whether the file was malicious.
- Whether missing entries mean no execution occurred.

## 14. Evidence Correlation

ShimCache should be correlated before making strong claims.

| Correlating Artifact | Added Value |
| --- | --- |
| Amcache | Path, program metadata, hash-related fields. |
| Prefetch | Stronger execution-related timing. |
| MFT | File existence, timestamps, deleted record status. |
| USN Change Journal | File creation, write, rename, and deletion sequence. |
| Event Logs 4688 | Process creation and command line if enabled. |
| SRUM | Application resource or network usage leads. |
| EDR telemetry | Parent process, command line, user session, hash, network behavior. |

### Correlation Map

```text
ShimCache: suspicious executable path
        |
        +--> MFT / USN: file existed and changed
        |
        +--> Amcache: file metadata and hash context
        |
        +--> Prefetch: execution-related evidence
        |
        +--> 4688 / EDR: parent process, command line, account
```

## 15. Investigation Walkthrough

### Scenario

An investigator reviews a host where attackers may have executed tools from a network share.

### Step 1: Parse ShimCache

Observation:

- ShimCache contains a path similar to:

```text
\\10.10.4.25\tools\adfind.exe
```

Inference:

- Windows compatibility data contains an entry for an executable on a network path.
- The path is suspicious in the context of intrusion investigation.

### Step 2: Avoid Premature Execution Claims

Observation:

- The entry has a last modified timestamp.

Interpretation:

- Do not call the timestamp execution time.
- Treat the entry as a lead requiring correlation.

### Step 3: Correlate With Event Logs

Observation:

- Event logs show a network logon from `10.10.4.25`.
- Process creation telemetry, if enabled, shows command execution related to `adfind.exe`.

Inference:

- Process telemetry can support execution and attribution.

### Step 4: Correlate With Other Artifacts

Observation:

- Amcache or Prefetch may contain matching evidence.
- MFT may not contain the executable if it ran from a network path.

Inference:

- The network path and event log activity together may support lateral movement or remote tool execution.

### Step 5: Write the Finding

Precise wording:

```text
ShimCache contains an application compatibility entry for \\10.10.4.25\tools\adfind.exe. This path is suspicious and may indicate tool presence or execution-related compatibility processing. Because ShimCache timestamps are not reliable execution times, execution should be confirmed through process creation telemetry, Prefetch where applicable, Amcache, command history, or EDR data.
```

## 16. ASCII Timeline

```text
03:18:40  Event log: network logon from 10.10.4.25
03:20:xx  ShimCache: entry exists for \\10.10.4.25\tools\adfind.exe
03:21:05  4688 / EDR: process execution if available
03:22:30  Event logs / EDR: directory enumeration activity
```

The ShimCache entry is a lead. The process event is stronger execution evidence.

## 17. Investigator's Mindset

ShimCache rewards skepticism. It can point to important executables, but it punishes lazy wording.

Ask:

- Which Windows version produced this ShimCache?
- Which parser version interpreted it?
- Is the timestamp file metadata or an execution-related field?
- Does the entry path look suspicious in context?
- Is there Prefetch, Amcache, event log, or EDR evidence for execution?
- Could the file have been observed without being executed?
- What exact claim can I support?

Use ShimCache to find paths. Use correlation to prove behavior.

## 18. Key Takeaways

- ShimCache/AppCompatCache is an application compatibility artifact stored in the SYSTEM hive.
- It can preserve executable paths and file metadata.
- It is useful for suspicious executable discovery and deleted-file leads.
- Last modified timestamps are not execution timestamps.
- Execution interpretation is version- and parser-dependent.
- ShimCache does not provide user, command line, parent process, or network behavior by itself.
- Strong conclusions require correlation with Amcache, Prefetch, MFT, USN, event logs, and EDR telemetry.

## 19. Review Questions

1. Why does Windows maintain ShimCache/AppCompatCache?
2. Where is ShimCache commonly stored?
3. Why is last modified time not execution time?
4. What artifacts would you use to confirm a ShimCache execution hypothesis?
5. Why is Windows version important when interpreting ShimCache?

## 20. References

- Eric Zimmerman, "AppCompatCacheParser": https://github.com/EricZimmerman/AppCompatCacheParser
- SANS, "AppCompatCacheParser": https://www.sans.org/tools/appcompatcacheparser
- Mandiant, "Caching Out: The Value of Shimcache for Investigators": https://cloud.google.com/blog/topics/threat-intelligence/caching-out-the-val/
- Magnet Forensics, "ShimCache vs AmCache: Key Windows Forensic Artifacts": https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/
- Cyber Triage, "ShimCache and AmCache Forensic Analysis 2026": https://www.cybertriage.com/blog/shimcache-and-amcache-forensic-analysis-2026/
