# Chapter 6: Amcache

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why Windows maintains `Amcache.hve`.
- Identify the forensic value of Amcache file and program entries.
- Interpret Amcache as application compatibility and inventory evidence, not a simple execution log.
- Correlate Amcache with Prefetch, MFT, USN, event logs, ShimCache/AppCompatCache, and EDR telemetry.
- Avoid common mistakes involving hashes, timestamps, and execution claims.

## 2. Introduction

Amcache is a Windows artifact stored in a registry hive file commonly located at:

```text
C:\Windows\AppCompat\Programs\Amcache.hve
```

It is associated with Windows application compatibility and program inventory behavior. Parsed Amcache data can include file paths, program information, timestamps, publisher or version metadata, and hashes for some files.

For investigators, Amcache is useful because it can show that Windows recorded information about executables, installed programs, drivers, and related files. It often helps answer:

- Did Windows record this program on the host?
- What path was associated with the executable?
- What file metadata did Windows store?
- Is there a hash or publisher field to support identification?
- Does this artifact support or contradict Prefetch and event log evidence?

Amcache is valuable, but it must be interpreted carefully. It is not a perfect execution ledger.

## 3. Why Windows Created This Artifact

Windows uses application compatibility infrastructure to help programs run correctly across versions and configurations. The operating system and compatibility components may record metadata about programs, executables, drivers, and installed applications.

Amcache exists to support that Windows functionality. Its forensic value comes from the metadata Windows stores while performing compatibility and inventory-related work.

Because the artifact is not designed as a DFIR audit log, investigators should avoid treating every Amcache entry as proof of human execution.

## 4. Why Investigators Care

Amcache helps identify files and programs that may not be obvious from current file system state alone.

| Investigative Need | Amcache Contribution |
| --- | --- |
| Program presence | May show that Windows recorded a program or executable. |
| Path context | Can store full paths useful for resolving same-named files. |
| Hash context | May include SHA-1-style hash values depending on entry and version. |
| Version metadata | May show company name, product name, file description, or version. |
| Deleted file leads | May preserve entries after the file is gone. |
| Execution correlation | Can support Prefetch, event log, and EDR findings. |
| External media leads | May help identify programs run or observed from nonstandard paths. |

Amcache is especially useful when Prefetch is absent or when the investigator needs path and metadata context for a suspicious executable.

## 5. Internal Structure

Investigators do not need to memorize every key, but they should understand that Amcache is a hive-like file using a registry format.

Common parser output distinguishes between:

| Entry Type | Practical Meaning |
| --- | --- |
| File entries | Metadata about files Windows recorded. |
| Program entries | Metadata about installed or inventoried programs. |
| Driver entries | Driver-related metadata in some versions. |

Different Windows versions store different structures. Parser support matters. A field available on one host may not exist on another.

## 6. Data Stored

Parsed Amcache output may include:

- full path
- file name
- extension
- file size
- SHA-1 or hash-like values where available
- first observed or last modified style timestamps depending on parser and version
- publisher
- company name
- product name
- file description
- version
- program identifier
- source path or install-related fields

Hash interpretation requires care. Some Amcache hash values may not represent a full-file cryptographic hash in the way investigators expect. Verify hash behavior with the parser documentation and, when possible, hash the original file directly.

## 7. Acquisition Methods

Acquire Amcache from:

```text
C:\Windows\AppCompat\Programs\Amcache.hve
```

Also consider related transaction logs when available:

```text
C:\Windows\AppCompat\Programs\Amcache.hve.LOG1
C:\Windows\AppCompat\Programs\Amcache.hve.LOG2
```

Acquisition options include:

- full disk image
- targeted triage collection
- endpoint response file retrieval
- live collection with tools that handle locked files

Document:

- host name
- Windows version
- collection time in UTC
- source path
- parser and version
- whether hive transaction logs were collected
- whether the system was live

## 8. Interpretation

Amcache should be interpreted as Windows-recorded program and file metadata.

Example observation:

```text
Amcache entry:
Path: C:\Users\alex\AppData\Local\Temp\winupdate.exe
SHA-1: <parser-provided value>
Publisher: Unknown
File description: Windows Update Service
```

Reasonable inference:

- Windows recorded metadata for an executable at that path.
- The path and suspicious self-description make the file worth further investigation.
- The hash-like value can support pivoting if validated.

Unsupported conclusion:

- "The file conclusively executed."

Amcache can be execution-related, but it should not be used alone as final proof of execution. Correlate with Prefetch, Security 4688, Sysmon, EDR telemetry, or other execution artifacts.

## 9. Strengths

Amcache has several strengths:

- Stores useful path and program metadata.
- Can persist after the original file is deleted.
- Helps resolve same-named executable ambiguity.
- May provide hash values useful for triage and pivoting.
- Useful when Prefetch is missing or incomplete.
- Supports program inventory and installed application analysis.
- Correlates well with MFT, Prefetch, and event logs.

Amcache often provides the path and metadata that make other execution artifacts more meaningful.

## 10. Weaknesses

Amcache has important limitations:

- It is not a complete execution log.
- Behavior varies across Windows versions.
- Field meanings can differ by parser and structure.
- Hash values may require validation.
- Timestamps can be misunderstood.
- Entries can reflect program inventory or compatibility processing, not necessarily user execution.
- It usually does not provide process parent, command line, or user intent.

Treat Amcache as strong supporting evidence, not a standalone verdict.

## 11. Common Mistakes

### Mistake 1: Calling Every Entry Execution

An Amcache entry means Windows recorded metadata. It does not always mean the program executed in the way an investigator imagines.

### Mistake 2: Trusting Hashes Without Validation

If the original file is available, hash it directly. Do not assume every parser-provided Amcache hash is equivalent to a full-file SHA-1 hash suitable for direct reputation lookup.

### Mistake 3: Ignoring Windows Version Differences

Amcache structure and fields vary. Always interpret output in the context of the target operating system and parser version.

### Mistake 4: Confusing File Metadata With File Behavior

Company name, file description, and product name are file metadata. Attackers can forge or manipulate version information.

### Mistake 5: Treating Path Alone As Attribution

A path under a user's profile does not prove that user knowingly executed the file.

## 12. Questions It Can Answer

Amcache can often help answer:

- Did Windows record metadata about this executable or program?
- What path was associated with the file?
- What version, publisher, or product metadata was recorded?
- Is there a hash-like value for pivoting?
- Does the entry support a suspicious file's existence after deletion?
- Does Amcache align with Prefetch, MFT, and event log evidence?

## 13. Questions It Cannot Answer

Amcache cannot answer by itself:

- Whether the executable conclusively ran.
- Which user launched the program.
- What command line was used.
- Which parent process launched it.
- Whether the file was malicious.
- Whether the file's embedded metadata is truthful.
- Whether no entry means the program was never present.

## 14. Evidence Correlation

Amcache works best as a supporting artifact.

| Correlating Artifact | Added Value |
| --- | --- |
| Prefetch | Stronger execution-related evidence and run timing. |
| MFT | File existence, timestamps, allocation, deleted record context. |
| USN Change Journal | Creation, write, rename, and delete activity. |
| Event Logs 4688 | Process creation and command line if enabled. |
| ShimCache/AppCompatCache | Additional application compatibility evidence. |
| SRUM | Application resource and network usage context. |
| Browser artifacts | Download source. |
| EDR telemetry | Process lineage, user, hash, and network behavior. |

### Correlation Map

```text
Amcache: metadata for suspicious executable path
        |
        +--> MFT / USN: file existed and changed near incident time
        |
        +--> Prefetch: Windows recorded execution-related activity
        |
        +--> 4688 / EDR: parent process, user session, command line
        |
        +--> Hash / file metadata: reputation and malware analysis pivot
```

## 15. Investigation Walkthrough

### Scenario

An analyst finds Prefetch evidence for `WINUPDATE.EXE`, but there are multiple same-named files across the system.

### Step 1: Search Amcache

Observation:

- Amcache contains an entry for `C:\Users\alex\AppData\Local\Temp\winupdate.exe`.
- Metadata shows an unknown publisher and suspicious file description.

Inference:

- Windows recorded metadata for a suspicious-path executable matching the Prefetch executable name.

### Step 2: Correlate File System Evidence

Observation:

- MFT and USN show the same path was created shortly before the Prefetch last run time.

Inference:

- The Amcache entry likely relates to the same suspicious executable observed in file system artifacts.

### Step 3: Validate Hash

Observation:

- The original file is no longer present, but Amcache includes a parser-provided hash-like value.

Inference:

- The hash may support pivoting, but direct file hashing is impossible unless the file is recovered from quarantine, backup, EDR, memory, or disk.

### Step 4: Identify Execution Chain

Observation:

- Event 4688 or EDR telemetry shows PowerShell launching the path.

Inference:

- Execution is now supported by process telemetry, with Amcache providing metadata and path context.

### Step 5: Write the Finding

Precise wording:

```text
Amcache contains metadata for C:\Users\alex\AppData\Local\Temp\winupdate.exe, including suspicious version information and a parser-provided hash value. MFT and USN records show the file was created shortly before Prefetch recorded execution-related activity. Process telemetry is required to confirm parent process, command line, and user session.
```

## 16. ASCII Timeline

```text
03:22:11  MFT / USN: winupdate.exe created in Temp
03:22:xx  Amcache: Windows records metadata for winupdate.exe
03:23:02  Prefetch: execution-related timestamp
03:23:03  4688 / EDR: process creation if available
03:25:40  USN: file deleted
```

The Amcache timestamp should be interpreted according to parser documentation and Windows version.

## 17. Investigator's Mindset

Use Amcache to strengthen identity and path context, not to shortcut execution analysis.

Ask:

- What exact Amcache structure did the parser read?
- What Windows version produced the hive?
- Is the path unique or shared by same-named files?
- Is the hash directly comparable to a full-file hash?
- Does Prefetch or process telemetry support execution?
- Does file metadata look trustworthy or attacker-controlled?
- What artifact can prove the next claim?

Amcache is most useful when it helps connect file identity to other evidence.

## 18. Key Takeaways

- Amcache is stored in `C:\Windows\AppCompat\Programs\Amcache.hve`.
- It records Windows application compatibility and program metadata.
- It is useful for path, file metadata, program inventory, and hash-related pivots.
- It should not be treated as a complete execution log.
- Hash and timestamp fields require parser-aware interpretation.
- Amcache is strongest when correlated with Prefetch, MFT, USN, event logs, and EDR telemetry.

## 19. Review Questions

1. Why does Windows maintain Amcache?
2. Why is Amcache not the same as Prefetch?
3. What Amcache fields are useful for identifying suspicious executables?
4. Why should parser-provided hashes be validated?
5. Which artifacts would you use to prove execution after finding an Amcache entry?

## 20. References

- Eric Zimmerman, "AmcacheParser": https://github.com/EricZimmerman/AmcacheParser
- Eric Zimmerman Tools, "AmcacheParser": https://ericzimmerman.github.io/
- SANS, "AmcacheParser": https://www.sans.org/tools/amcacheparser
- Magnet Forensics, "ShimCache vs AmCache: Key Windows Forensic Artifacts": https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/
- Kaspersky Securelist, "AmCache artifact: forensic value and a tool for data extraction": https://securelist.com/amcache-forensic-artifact/117622/
- Forensics Artifacts Knowledge Base, "AMCache": https://artifacts-kb.readthedocs.io/en/latest/sources/windows/AMCache.html
- Blanche Lagny, ANSSI, "Analysis of the AmCache": https://cyber.gouv.fr/documents/634/anssi-coriin_2019-analysis_amcache.pdf
