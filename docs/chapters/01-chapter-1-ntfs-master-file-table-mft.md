# Chapter 1: NTFS Master File Table (MFT)

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why the New Technology File System (NTFS) uses the Master File Table (MFT).
- Identify the core investigative value of MFT records.
- Distinguish direct observations from inferences drawn from file system metadata.
- Recognize common timestamp interpretation mistakes.
- Correlate MFT evidence with the USN Change Journal, event logs, Prefetch, Amcache, and user activity artifacts.

## 2. Introduction

The Master File Table (MFT) is one of the most important Windows file system artifacts. On an NTFS volume, it acts as the file system's central index. Files, directories, and NTFS metadata files are represented through MFT records.

For investigators, the MFT is valuable because it helps answer a basic but powerful question: **what file system objects existed on this volume, and what metadata did NTFS record about them?**

That question sounds simple. In practice, it supports many incident response tasks:

- finding suspicious binaries staged in user-writable directories
- identifying recently created or deleted files
- reconstructing attacker tool placement
- spotting unusual filename patterns
- correlating file timestamps with execution, logon, and persistence evidence
- detecting possible timestomping or cleanup activity

The MFT should not be treated as a complete history of user behavior. It is file system metadata. It records what NTFS needed to manage files, not what an investigator wishes had happened. The value comes from careful correlation.

## 3. Why Windows Created This Artifact

Windows uses NTFS to manage files and directories on many system volumes. NTFS needs a reliable way to track where files are, what attributes belong to them, how large they are, how they are named, and where their content resides.

The MFT exists to provide that structure. Each NTFS volume has an MFT. Microsoft describes the MFT as storing the information required to retrieve files from an NTFS partition, with at least one MFT entry for every file on an NTFS volume, including metadata files used by NTFS itself.

This is an operating system need, not a forensic feature. NTFS creates and updates MFT records so the file system can function. Investigators benefit because those same records often preserve useful metadata long after the original user action is complete.

## 4. Why Investigators Care

The MFT is often one of the first artifacts examined during file system timeline analysis because it gives broad coverage across the volume. It can reveal suspicious files even when execution evidence is missing or when logs have rolled over.

Investigators care about the MFT because it can provide:

| Investigative Need | MFT Contribution |
| --- | --- |
| File existence | Shows records for allocated files and sometimes remnants of deleted records. |
| File naming | Preserves filename attributes, including parent reference information. |
| File placement | Helps reconstruct paths through parent-child relationships. |
| File timing | Provides creation, modification, access, and metadata-change timestamps. |
| File size | Shows logical and allocated size information through attributes. |
| Deletion leads | Deleted MFT records may remain until reused. |
| Timestomping leads | Timestamp disagreement can suggest manipulation or unusual file operations. |

The MFT is especially useful during triage because it can quickly surface file system anomalies across the entire volume.

## 5. Internal Structure

Only a few internal concepts are necessary for practical investigation.

### MFT Records

An MFT record is a structured entry that describes a file system object. Most files have one base record. Some files require additional records when their metadata does not fit in a single record.

### Attributes

NTFS represents file information as attributes. Common examples include:

| Attribute | Practical Meaning |
| --- | --- |
| `$STANDARD_INFORMATION` | Core timestamps and file metadata used by NTFS. |
| `$FILE_NAME` | Filename, parent directory reference, namespace, and another set of timestamps. |
| `$DATA` | File content or pointers to where content resides. |
| `$ATTRIBUTE_LIST` | Points to additional records when attributes are too large or fragmented. |

Small file content can sometimes be resident inside an MFT record. Larger content is nonresident, meaning the MFT record describes where the content is stored elsewhere on disk.

### File Reference Numbers

MFT records are referenced by file reference values. These values help NTFS identify records and parent-child relationships. Investigators use them to reconstruct paths and to understand whether a record has been reused.

## 6. Data Stored

Depending on the parser and the state of the record, MFT-derived output may include:

- record number
- sequence number
- allocated or deleted status
- base record reference
- parent record reference
- filename
- extension
- full path reconstructed by the parser
- file size
- flags such as directory, archive, hidden, or system
- `$STANDARD_INFORMATION` timestamps
- `$FILE_NAME` timestamps
- alternate data stream indicators
- attribute details

The most commonly discussed timestamps are:

| Timestamp | Common Label | What It Usually Represents |
| --- | --- | --- |
| Creation time | Created | When the file system object was created in that location or under that record context. |
| Last modification time | Modified | When file content was last written. |
| MFT change time | Entry modified / metadata changed | When file system metadata for the record changed. |
| Last access time | Accessed | When last access tracking recorded access, subject to important limitations. |

Do not assume every timestamp is equally reliable. Last access time is frequently weak evidence on modern Windows systems because NTFS last access updates can be disabled or delayed.

## 7. Acquisition Methods

The MFT can be acquired in several ways. The best method depends on whether the investigator is performing live response, endpoint triage, or full disk analysis.

| Method | Use Case | Notes |
| --- | --- | --- |
| Full disk image | Deep forensic examination | Preserves volume context and unallocated space. |
| Logical artifact collection | Triage or remote collection | Faster, but may miss surrounding disk context. |
| Endpoint response collection | Enterprise incident response | Useful at scale; preserve tool logs and collection scope. |
| Forensic parser against image | Offline analysis | Preferred when evidence preservation is required. |

Common practical approaches include collecting `$MFT` from the root of an NTFS volume, parsing it with a forensic tool, and exporting structured results such as CSV or bodyfile output for timeline analysis.

When collecting from a live system, document:

- hostname
- volume collected
- collection time in Coordinated Universal Time (UTC)
- tool name and version
- command line or collection profile
- hash of collected artifact if possible
- whether the collection had administrative or raw volume access

## 8. Interpretation

The MFT gives observations. The investigator supplies interpretation.

Example observations:

- `C:\Users\alex\AppData\Local\Temp\winupdate.exe` appears in parsed MFT output.
- The record is marked allocated.
- The file has a creation timestamp of `2026-07-14 03:22:11 UTC`.
- The metadata-change timestamp is later than the content-modification timestamp.
- The parent directory is a user profile temporary directory.

Careful inference:

- The file likely existed at the parsed path at acquisition time if the record is allocated and the reconstructed path is valid.
- The filename and location are suspicious because they resemble system naming but reside in a user-writable temporary directory.
- The later metadata-change time may reflect rename, permission change, attribute change, timestamp manipulation, or another metadata operation.

Unsupported conclusion:

- "The attacker executed this file."

Execution requires correlation. Use Prefetch, Amcache, ShimCache/AppCompatCache, event logs, command-line telemetry, EDR data, memory evidence, or other execution artifacts before making that claim.

## 9. Strengths

The MFT has several strengths:

- Broad volume coverage.
- Useful for both allocated and some deleted file records.
- Strong file system context.
- Valuable timestamps for timeline building.
- Parent-child references that support path reconstruction.
- Useful for finding suspicious staging locations.
- Helpful for detecting conflicts between file system metadata and execution artifacts.

The MFT is also useful when other logs are absent. A system may have limited event log retention, no command-line logging, and no EDR telemetry, but the file system still needs metadata to operate.

## 10. Weaknesses

The MFT also has important limitations:

- It does not prove execution.
- Deleted records can be reused.
- Path reconstruction may be incomplete if parent records are missing or reused.
- Timestamps can be changed by normal operations, attacker activity, restoration, copying, extraction, or tooling.
- Last access time is often unreliable.
- Time zone handling errors can distort analysis.
- Live collection can alter the system.
- Parser output can hide complexity if the investigator does not understand the underlying attributes.

The MFT is not a standalone source of certainty. It is a structured source of file system evidence.

## 11. Common Mistakes

### Mistake 1: Treating Creation Time As Download Time

Creation time means the file system object was created in that context. It does not automatically mean the file was downloaded at that time. A copied file, extracted archive member, restored file, or attacker-staged payload may all produce creation timestamps that need correlation.

### Mistake 2: Treating MFT Change Time As Content Modification

MFT change time reflects metadata changes to the file record. It is not the same as file content modification. A rename or permission change can update metadata without changing file content.

### Mistake 3: Ignoring `$FILE_NAME` Timestamps

Many tools show both `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps. Differences between them can be meaningful. They can also arise from legitimate file operations. Treat discrepancies as leads, not automatic proof of timestomping.

### Mistake 4: Overtrusting Last Access Time

Last access updates can be disabled or delayed. On modern Windows systems, last access time should usually be considered weak evidence unless system configuration and supporting artifacts make it stronger.

### Mistake 5: Forgetting Record Reuse

Deleted MFT records may remain visible until reused. Once reused, old information can be overwritten. A deleted record is a lead, not a guarantee that every previous detail is still intact.

## 12. Questions It Can Answer

The MFT can often help answer:

- Did a file or directory with this name exist on the volume?
- Where was it located according to available parent references?
- Was the record allocated or deleted at acquisition time?
- What timestamps did NTFS store for the file system object?
- Did metadata timestamps differ from filename timestamps?
- Were suspicious files placed in user-writable or unusual directories?
- Are there signs of file creation, deletion, renaming, or metadata changes?

## 13. Questions It Cannot Answer

The MFT cannot answer by itself:

- Who created the file?
- Which process created the file?
- Whether the file executed.
- Whether the file was malicious.
- Whether a timestamp is truthful.
- Whether a user intentionally interacted with the file.
- Whether the file was transferred from the internet, copied from USB, extracted from an archive, or dropped by malware.

Those questions require correlation.

## 14. Evidence Correlation

MFT evidence becomes much stronger when correlated with other artifacts.

| Correlating Artifact | What It Adds |
| --- | --- |
| USN Change Journal | More granular file change activity, if records remain. |
| `$LogFile` | Transaction-level context for some NTFS operations. |
| Prefetch | Possible program execution evidence. |
| Amcache | Program inventory and execution-related leads. |
| ShimCache/AppCompatCache | Program presence and compatibility-related execution leads. |
| Event Logs | Logon, service creation, scheduled task, PowerShell, and security events. |
| SRUM | Network and application resource usage over time. |
| LNK files | User or shell interaction with files. |
| Jump Lists | Recent user activity and application-opened files. |
| Browser artifacts | Download source, time, and URL context. |
| EDR telemetry | Process lineage, command line, hash, and network behavior. |

### Evidence Correlation Map

```text
Suspicious file in MFT
        |
        +--> USN Journal: was it created, renamed, deleted, or overwritten?
        |
        +--> Prefetch / Amcache: is there evidence the file executed?
        |
        +--> Event Logs: was there related logon, service, task, or PowerShell activity?
        |
        +--> Browser / LNK / Jump Lists: did a user download or open it?
        |
        +--> EDR / Memory: what process touched it, and what did it do?
```

## 15. Investigation Walkthrough

### Scenario

An endpoint alert reports suspicious outbound traffic from a workstation. The alert identifies a process path:

```text
C:\Users\alex\AppData\Local\Temp\winupdate.exe
```

The investigator collects the MFT, event logs, Prefetch, Amcache, PowerShell logs, and browser artifacts.

### Step 1: Locate the File in MFT Output

Observation:

- The MFT contains an allocated record for `winupdate.exe`.
- The path resolves under a user's temporary directory.
- The filename resembles a Windows update component but is not located in a Windows system directory.

Initial assessment:

- Suspicious placement.
- Needs execution and origin correlation.

### Step 2: Compare Timestamps

Observation:

```text
Created:        2026-07-14 03:22:11 UTC
Modified:       2026-07-14 03:21:58 UTC
MFT changed:    2026-07-14 03:22:13 UTC
Accessed:       2026-07-14 03:22:11 UTC
```

Interpretation:

- Modified time is slightly earlier than creation time. This can happen when a file is copied or extracted while preserving original modification time.
- MFT changed shortly after creation, which could reflect normal metadata finalization, rename, attribute update, or another file system operation.
- Last access adds little without confirming last access update behavior.

Do not conclude timestomping from this alone.

### Step 3: Correlate Execution Evidence

Observation:

- Prefetch contains an entry for `WINUPDATE.EXE`.
- Amcache contains a record for the same path and file hash.
- Security or Sysmon logs, if available, show process creation around `2026-07-14 03:23 UTC`.

Inference:

- The file likely executed shortly after appearing in the temporary directory.
- The confidence increases if process creation telemetry includes the same path, hash, parent process, and command line.

### Step 4: Correlate Origin Evidence

Observation:

- Browser download history shows a download shortly before file creation.
- A PowerShell transcript or script block log shows a command writing to the same path.
- The USN Change Journal shows create and rename activity in the same directory.

Inference:

- The file may have been downloaded or staged by script. The exact origin depends on which artifact provides the strongest source evidence.

### Step 5: State the Finding Precisely

Poor wording:

```text
The suspicious program was downloaded and executed at 03:22.
```

Better wording:

```text
The MFT shows that winupdate.exe existed in C:\Users\alex\AppData\Local\Temp by 2026-07-14 03:22:11 UTC. The location and name are suspicious. Prefetch and process telemetry indicate execution shortly afterward. Browser and PowerShell artifacts should be used to determine whether the file was downloaded by the user, written by script, or staged by another process.
```

The second version separates evidence from inference and leaves room for additional facts.

## 16. ASCII Timeline

```text
2026-07-14 03:21:58  MFT Modified time for winupdate.exe
2026-07-14 03:22:11  MFT Created time for winupdate.exe
2026-07-14 03:22:13  MFT metadata-change time
2026-07-14 03:23:02  Prefetch / process telemetry indicates execution
2026-07-14 03:24:10  Network alert reports outbound connection
```

Investigator note: the timeline shows order. It does not, by itself, prove causation.

## 17. Investigator's Mindset

Use the MFT to find the file system story, then test that story against independent evidence.

A disciplined investigator asks:

- What does the MFT directly show?
- Which parser fields are derived rather than raw?
- Are parent references complete enough to trust the reconstructed path?
- Do `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps agree?
- Could normal file operations explain the timestamp pattern?
- Which artifact would prove or disprove execution?
- Which artifact would identify the process or user responsible?

The MFT is often the beginning of a finding, not the end.

## 18. Key Takeaways

- The MFT is the central NTFS metadata structure for files and directories.
- MFT evidence is excellent for file existence, placement, timestamps, and deletion leads.
- MFT timestamps must be interpreted carefully and correlated.
- MFT change time is metadata-change time, not content-modification time.
- Last access time is weak unless system behavior and configuration support it.
- The MFT does not prove execution, user intent, malware identity, or file origin by itself.
- Strong conclusions come from correlating the MFT with execution, logging, user activity, and endpoint telemetry.

## 19. Review Questions

1. Why is MFT evidence useful during intrusion reconstruction?
2. What is the difference between content modification time and MFT metadata-change time?
3. Why should last access time be treated cautiously?
4. What artifacts would you use to test whether a file found in the MFT executed?
5. What is the difference between observing timestamp disagreement and concluding timestomping?

## 20. References

- Microsoft Learn, "Master File Table (Local File Systems)": https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table
- Microsoft Learn, "Master File Table (Developer Notes)": https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table
- Microsoft Learn, "FILETIME structure": https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
- Microsoft Learn, "[MS-FSCC]: Time": https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a69cc039-d288-4673-9598-772b6083f8bf
- Microsoft Learn, "File Times": https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times
- Microsoft Learn, "fsutil behavior": https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
- Microsoft Learn, "[MS-FSA]: Appendix A: Product Behavior": https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4e3695bd-7574-4f24-a223-b4679c065b63
- Eric Zimmerman, "MFTECmd": https://github.com/EricZimmerman/MFTECmd
- Velociraptor artifact definition, "Windows.NTFS.MFT": https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/NTFS/MFT.yaml
