# Chapter 2: NTFS Update Sequence Number (USN) Change Journal

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why NTFS maintains the Update Sequence Number (USN) Change Journal.
- Describe what a USN record can and cannot prove.
- Use USN records to reconstruct file creation, deletion, rename, and modification activity.
- Correlate USN evidence with the MFT, `$LogFile`, execution artifacts, and event logs.
- Avoid common mistakes involving reason flags, timestamps, and journal rollover.

## 2. Introduction

The Update Sequence Number (USN) Change Journal is an NTFS feature that records changes to files, directories, and other NTFS objects on a volume. It is maintained per volume. As changes occur, NTFS appends records that identify the object changed and the type of change recorded.

For investigators, the USN Change Journal often provides the missing motion between MFT snapshots. The MFT can show that a file exists or that a deleted record remains. The USN Change Journal may show that the file was created, renamed, overwritten, closed, or deleted during a relevant period.

The journal is especially useful when answering questions like:

- Did the suspicious file appear recently?
- Was it renamed before execution?
- Was it deleted after the alert?
- Did a directory experience mass file modification?
- Is there evidence of staging, extraction, or cleanup?

The journal is not permanent history. It has size limits and older records are eventually overwritten.

## 3. Why Windows Created This Artifact

Windows did not create the USN Change Journal for investigators. NTFS uses it so applications and system services can efficiently learn what changed on a volume without repeatedly scanning the entire file system.

Microsoft describes the journal as a persistent log of changes made to files on a volume. Each record indicates the changed object and the type of change. New records are appended to the stream.

This design supports legitimate features such as indexing, backup, replication, and file synchronization. Forensics benefits because the same records can preserve recent file system activity.

## 4. Why Investigators Care

The USN Change Journal is valuable because it records file system activity as a sequence of change events. It can help reconstruct attacker behavior that is only partially visible in the MFT.

| Investigative Need | USN Contribution |
| --- | --- |
| File creation | May show when a file or directory was created. |
| Rename tracking | May show old and new names through rename reason flags. |
| Deletion evidence | May show delete activity even when file content is gone. |
| Staging detection | Can reveal bursts of creates and writes in temporary paths. |
| Ransomware triage | Can show large-scale file overwrite, rename, or delete patterns. |
| Cleanup analysis | Can show post-execution deletion or movement. |
| Timeline ordering | USN values and timestamps help sequence file system activity. |

The journal can be more event-like than the MFT. The MFT tells the investigator about file metadata state. The USN Change Journal tells the investigator that NTFS recorded a change.

## 5. Internal Structure

Only a practical subset of structure is needed for investigation.

### Journal Location

The journal is stored in NTFS metadata under `$Extend\$UsnJrnl`, commonly including the `$J` data stream that contains journal records.

### USN Records

USN records exist in multiple versions. Microsoft documents structures such as `USN_RECORD_V2`, `USN_RECORD_V3`, and `USN_RECORD_V4`. A parsed record commonly exposes:

- record length
- major and minor version
- file reference number
- parent file reference number
- USN value
- timestamp
- reason flags
- source information
- security identifier
- file attributes
- filename

### Reason Flags

Reason flags indicate categories of changes. A single record may contain multiple flags. Examples include file create, file delete, data overwrite, data extend, rename old name, rename new name, and close.

Reason flags should be read as file system change categories, not as full explanations of human behavior.

## 6. Data Stored

Parsed USN output typically includes:

| Field | Investigative Use |
| --- | --- |
| Timestamp | Places the change in time. |
| USN | Helps order records on the same volume. |
| Filename | Names the changed object at the time of the record. |
| File reference number | Links to MFT records. |
| Parent reference number | Helps reconstruct directory context. |
| Reason flags | Describes the type of file system change. |
| File attributes | Provides object type and attribute context. |
| Source info | May indicate system-originated change categories. |

The journal does not normally provide the process name, command line, username, or network source responsible for the change. Those must be obtained from other evidence.

## 7. Acquisition Methods

Investigators can acquire USN data through:

- full disk or volume imaging
- targeted collection of `$Extend\$UsnJrnl:$J`
- forensic collection frameworks
- endpoint response tools
- live queries through Windows APIs or forensic tooling

Document the collection method carefully. A parser working against a forensic image is different from a live collection on an active endpoint. Live systems continue generating USN records during collection.

Minimum documentation should include:

- volume identifier or drive letter
- collection time in UTC
- acquisition method
- tool and version
- whether the source was live or offline
- journal size and record range if available

## 8. Interpretation

A USN record is evidence that NTFS recorded a change to a file system object. Interpretation depends on reason flags, filename, parent reference, timestamp, and correlation.

Example observation:

```text
2026-07-14 03:22:11 UTC
Reason: FILE_CREATE | DATA_EXTEND | CLOSE
Name: winupdate.exe
Parent: C:\Users\alex\AppData\Local\Temp
```

Reasonable inference:

- NTFS recorded creation and data growth for `winupdate.exe` in the user's temporary directory.
- The file was likely written or copied into that directory around that time.

Unsupported conclusion:

- "Alex intentionally downloaded malware."

To reach that conclusion, the investigator would need user context, browser evidence, command execution evidence, process lineage, or other supporting artifacts.

## 9. Strengths

The USN Change Journal has several strengths:

- Records file system changes in sequence.
- Often captures creates, deletes, renames, writes, and closes.
- Useful for detecting short-lived files.
- Helpful for ransomware and mass-change investigations.
- Links to MFT file reference numbers.
- Can show rename chains better than a final MFT snapshot.
- Useful for validating or challenging timestamp interpretations.

It is particularly useful when an attacker deletes tooling after execution. Even if the file is gone, the journal may still show that it existed and changed.

## 10. Weaknesses

The USN Change Journal has important limits:

- It rolls over; older records are overwritten.
- It is volume-specific.
- It does not identify the responsible process by itself.
- It does not prove file execution.
- Reason flags can be misunderstood.
- Timestamps can still require time zone normalization.
- Parent path reconstruction depends on MFT context.
- Some file activity may be absent if records were overwritten before collection.

The journal is a recent-change artifact, not a complete file system history.

## 11. Common Mistakes

### Mistake 1: Treating Reason Flags As a Narrative

Reason flags are categories of file system change. They are not a full story. `DATA_OVERWRITE` does not explain why data was overwritten. `FILE_DELETE` does not identify who deleted the file.

### Mistake 2: Ignoring Journal Rollover

If the journal no longer contains records from the incident window, absence of evidence is not evidence of absence. The records may have aged out.

### Mistake 3: Assuming Rename Records Alone Provide the Full Path

Rename evidence often needs MFT parent-reference reconstruction. Without reliable parent context, the investigator may only have a filename and object reference.

### Mistake 4: Confusing USN Order With Global Time Order

USN values help order records on the same volume. They should not be compared as global sequence numbers across different volumes or systems.

### Mistake 5: Claiming Execution From File Creation

File creation and file execution are different events. Execution requires correlation with execution artifacts or process telemetry.

## 12. Questions It Can Answer

The USN Change Journal can often help answer:

- Was a file created, renamed, modified, or deleted during the available journal window?
- Did a suspicious file have a previous or later name?
- Did activity occur in a staging directory before execution evidence?
- Were many files modified or renamed in a short period?
- Does the file system show cleanup after an alert?
- Does USN timing support or contradict MFT timestamp interpretation?

## 13. Questions It Cannot Answer

The USN Change Journal cannot answer by itself:

- Which process caused the change.
- Which user intentionally caused the change.
- Whether the file executed.
- Whether the file was malicious.
- Whether the change came from a download, extraction, script, installer, malware, or user copy operation.
- Whether missing records prove that no change occurred.

## 14. Evidence Correlation

USN evidence is strongest when paired with other artifacts.

| Correlating Artifact | Added Value |
| --- | --- |
| MFT | Current or residual metadata, parent references, timestamps, allocation state. |
| `$LogFile` | Lower-level NTFS transaction context, often useful near the same time window. |
| Prefetch | Execution evidence for programs. |
| Amcache | Program inventory and execution-related metadata. |
| Event Logs | Logon, process, service, scheduled task, PowerShell, and security context. |
| Browser artifacts | Download origin and user activity context. |
| LNK / Jump Lists | User or shell interaction with files. |
| EDR telemetry | Process lineage, command line, hash, network connection, and user session. |

### Correlation Pattern

```text
USN: file created in Temp
  |
  +-- MFT: file still allocated, timestamps align
  |
  +-- Prefetch: same executable launched minutes later
  |
  +-- Event logs: user logged on interactively
  |
  +-- Browser history: download from suspicious URL
  |
  +-- EDR: process spawned PowerShell and made network connection
```

The final conclusion should reflect the combined evidence, not the USN record alone.

## 15. Investigation Walkthrough

### Scenario

An analyst is investigating suspected ransomware activity on a file server. Users report that shared documents were renamed with a new extension.

### Step 1: Identify Mass Rename Activity

Observation:

- USN records show many files with rename reason flags.
- The activity is concentrated under shared project directories.
- Records occur within a tight time window.

Inference:

- NTFS recorded mass rename activity consistent with a ransomware-like pattern.

### Step 2: Look for Preceding File Writes

Observation:

- Before the rename burst, USN records show data overwrite or data extend activity on many files.

Inference:

- Files may have been modified before rename. This supports an encryption or overwrite hypothesis, but file content analysis is needed to confirm.

### Step 3: Correlate Process Evidence

Observation:

- Event logs or EDR telemetry show a process running under a service account during the same period.
- The process path appears in Prefetch or Amcache on the affected host.

Inference:

- The process is a candidate cause of the mass file changes.

### Step 4: Validate Scope

Observation:

- USN records show affected directories and filenames.
- MFT output shows which renamed files remain allocated.

Inference:

- The investigator can estimate affected scope and prioritize recovery.

### Step 5: Write the Finding Carefully

Precise wording:

```text
USN records on the data volume show a high-volume sequence of file overwrite and rename activity between 2026-07-14 01:18:22 UTC and 2026-07-14 01:24:09 UTC. The affected paths are concentrated under the shared project directories. EDR process telemetry from the same interval should be used to attribute the activity to a specific process and account.
```

## 16. ASCII Timeline

```text
01:18:22  USN: DATA_OVERWRITE on multiple shared documents
01:18:25  USN: RENAME_OLD_NAME / RENAME_NEW_NAME sequence begins
01:19:10  USN: hundreds of renamed files under \\Share\Projects
01:22:44  EDR: suspicious process still active
01:24:09  USN: rename burst ends
01:25:31  Event log: service stopped / process terminated
```

The timeline supports sequencing. Attribution requires process and account evidence.

## 17. Investigator's Mindset

Use the USN Change Journal to detect movement in the file system. Ask what changed, when it changed, and how those changes relate to other evidence.

Good investigative questions include:

- Is this change isolated or part of a burst?
- Does the record show creation, rename, write, delete, or close activity?
- Does the same file reference appear under multiple names?
- Does MFT data support the reconstructed path?
- Did execution evidence occur before or after the file change?
- Could backup, indexing, antivirus, sync software, or installation activity explain the pattern?

The USN Change Journal is excellent for finding leads. It still needs corroboration before strong conclusions.

## 18. Key Takeaways

- The USN Change Journal records NTFS file system changes on a volume.
- It is useful for creation, deletion, rename, write, and mass-change investigations.
- USN values help sequence records on the same volume.
- Reason flags describe change categories, not user intent.
- The journal rolls over, so missing records may simply be gone.
- USN evidence does not identify the responsible process or prove execution by itself.
- Strong findings correlate USN records with MFT, `$LogFile`, execution artifacts, event logs, and endpoint telemetry.

## 19. Review Questions

1. How does the USN Change Journal differ from the MFT?
2. Why is journal rollover important during incident response?
3. What does a rename reason flag prove, and what does it not prove?
4. Which artifacts would you use to identify the process responsible for a USN-recorded file change?
5. How can USN records help investigate ransomware-like activity?

## 20. References

- Microsoft Learn, "fsutil usn": https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn
- Microsoft Learn, "USN_RECORD_V2 structure": https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
- Microsoft Learn, "USN_RECORD_V4 structure": https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v4
- Microsoft Learn, "READ_USN_JOURNAL_DATA_V0 structure": https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-read_usn_journal_data_v0
- Microsoft Learn, "Walking a Buffer of Change Journal Records": https://learn.microsoft.com/en-us/windows/win32/fileio/walking-a-buffer-of-change-journal-records
- Eric Zimmerman, "MFTECmd": https://github.com/EricZimmerman/MFTECmd
- Velociraptor artifact definition, "Windows.NTFS.MFT": https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/NTFS/MFT.yaml
