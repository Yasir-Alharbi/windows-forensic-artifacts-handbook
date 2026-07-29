# Chapter 10: ShellBags

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why Windows creates ShellBag registry data.
- Locate ShellBag artifacts in user registry hives.
- Interpret ShellBags as folder navigation and view-state evidence.
- Use ShellBags to investigate local, removable, network, and deleted folder activity.
- Correlate ShellBags with LNK files, Jump Lists, MFT, USN, event logs, and external device artifacts.

## 2. Introduction

ShellBags are Windows Registry artifacts that record folder view settings and shell navigation state. When a user browses folders through File Explorer or shell-mediated interfaces, Windows may store information about those folders so it can remember view preferences such as layout, sorting, icon size, and window state.

For investigators, ShellBags are valuable because they can preserve evidence that a user profile encountered or browsed to a folder path. This can include folders on local disks, removable media, network shares, compressed archives, or locations that no longer exist.

ShellBags are not file-open evidence by themselves. They are folder-level shell evidence. If the question is "did the user open this document," ShellBags may support folder access, but LNK files, Jump Lists, application MRUs, and document metadata are needed for file-level conclusions.

## 3. Why Windows Created This Artifact

Windows created ShellBag data to improve user experience. Users expect File Explorer to remember how folders were displayed. ShellBags help preserve that shell view state across sessions.

The forensic value is incidental. Windows records folder state for usability, and investigators can use that record to reconstruct folder navigation and storage awareness.

## 4. Why Investigators Care

ShellBags help answer whether a user profile has evidence of browsing to a folder, including locations that are no longer mounted or present.

| Investigative Need | ShellBag Contribution |
| --- | --- |
| Folder access leads | Shows folders represented in shell view state. |
| Deleted folder leads | May preserve paths after deletion. |
| Removable media analysis | Can show folders browsed on USB or external drives. |
| Network share awareness | May preserve browsed UNC paths. |
| User profile context | Stored in user hives, supporting per-user analysis. |
| Data theft investigations | Can show browsing of sensitive folders before transfer. |
| Timeline support | Some keys and shell items include timestamps useful for correlation. |

ShellBags are especially useful in insider threat, data staging, USB usage, and network share browsing investigations.

## 5. Internal Structure

ShellBag data is commonly found in user registry hives, especially `NTUSER.DAT` and `UsrClass.dat`.

Common paths include areas under:

```text
NTUSER.DAT\Software\Microsoft\Windows\Shell
UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell
```

Important concepts:

| Concept | Practical Meaning |
| --- | --- |
| BagMRU | Tree-like structure representing browsed folders. |
| Bags | Stores folder view settings. |
| Shell items | Binary structures that can represent folder names, paths, timestamps, and device context. |
| User hive | Associates evidence with a specific user profile. |

Investigators usually use forensic parsers because manual interpretation is tedious and error-prone.

## 6. Data Stored

Parsed ShellBag output may include:

- reconstructed folder path
- user profile or hive source
- registry key path
- last write times
- shell item timestamps
- folder names
- drive or volume-related details
- network share paths
- removable media folder references
- parser-derived "first explored" or "last explored" style fields depending on tool

Timestamp interpretation requires care because ShellBag entries may contain multiple timestamps from different structures.

## 7. Acquisition Methods

Acquire user hives:

```text
C:\Users\<user>\NTUSER.DAT
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

Also collect transaction logs:

```text
NTUSER.DAT.LOG1
NTUSER.DAT.LOG2
UsrClass.dat.LOG1
UsrClass.dat.LOG2
```

Acquisition options include:

- full disk image
- user profile triage collection
- endpoint response file retrieval
- live collection with registry-aware tools

Document:

- user profile path
- hive paths and hashes
- user SID
- collection time in UTC
- parser and version
- whether transaction logs were collected
- whether source was live or offline

## 8. Interpretation

ShellBags support folder navigation or shell view-state evidence.

Example observation:

```text
Hive: C:\Users\alex\AppData\Local\Microsoft\Windows\UsrClass.dat
Parsed path: E:\ClientData\Acquisition\
ShellBag timestamp: 2026-07-14 01:52:33 UTC
```

Reasonable inference:

- Alex's user profile contains ShellBag evidence for a folder path on drive `E:`.
- The user shell likely encountered or browsed that folder.
- This supports a lead that removable or external storage may have been accessed.

Unsupported conclusion:

- "Alex copied client data to USB."

To support copying, correlate with USB device artifacts, MFT/USN activity on source and destination volumes, LNK files, Jump Lists, file access logs, EDR telemetry, and data loss prevention logs.

## 9. Strengths

ShellBags have several strengths:

- Per-user folder navigation context.
- Can preserve deleted or no-longer-mounted folder paths.
- Useful for removable media and network share investigations.
- Helpful for reconstructing folder awareness.
- Strong complement to LNK files and Jump Lists.
- Useful when file content is gone but navigation traces remain.

ShellBags often answer "did this user profile have shell evidence for this folder path?"

## 10. Weaknesses

ShellBags have important limitations:

- They do not prove a file was opened.
- They do not prove files were copied.
- They do not prove user intent.
- Timestamp interpretation can be complex.
- Parser-derived fields must be understood.
- Some folder access paths may not create ShellBag entries.
- Registry transaction logs may affect completeness.
- Malware or command-line access may bypass shell navigation artifacts.

ShellBags are folder-level evidence, not complete user behavior reconstruction.

## 11. Common Mistakes

### Mistake 1: Treating Folder Access As File Access

Browsing a folder does not prove opening a specific file inside it.

### Mistake 2: Treating ShellBag Evidence As Copy Evidence

ShellBags may support that a folder was browsed. Copy activity needs file system, USB, EDR, or other transfer evidence.

### Mistake 3: Ignoring User Hive Source

Always identify which user's hive contains the evidence.

### Mistake 4: Overstating Timestamp Meaning

ShellBag timestamps can come from registry key last writes or embedded shell items. Know what the parser field represents.

### Mistake 5: Forgetting Network and Removable Context

ShellBags can contain paths that refer to network shares or removable media. Correlate with device and network artifacts before drawing conclusions.

## 12. Questions It Can Answer

ShellBags can often help answer:

- Does a user's hive contain evidence for this folder path?
- Did the user profile likely browse a removable drive folder?
- Did the user profile likely browse a network share?
- Are there traces of deleted or missing folders?
- Does folder navigation align with LNK, Jump List, and file system evidence?

## 13. Questions It Cannot Answer

ShellBags cannot answer by themselves:

- Whether a specific file was opened.
- Whether files were copied.
- Whether data was exfiltrated.
- Whether the user intentionally browsed the folder.
- Which process performed a copy operation.
- Whether missing ShellBag entries mean no folder access occurred.

## 14. Evidence Correlation

ShellBags become much stronger when combined with file and device artifacts.

| Correlating Artifact | Added Value |
| --- | --- |
| LNK files | Shortcut target paths, file interaction, removable device context. |
| Jump Lists | Recent application/file activity. |
| MFT / USN | File creation, deletion, rename, and copy patterns. |
| USB artifacts | Device serial, mount time, drive letter, volume context. |
| Event Logs | Logon session and device/service events. |
| Browser artifacts | Cloud storage or download/upload context. |
| EDR telemetry | Process activity, file writes, copy tools, network transfers. |
| SRUM | Application network usage context. |

### Correlation Map

```text
ShellBag: user profile browsed sensitive folder
        |
        +--> LNK / Jump List: file-level interaction?
        |
        +--> USB artifacts: was removable media mounted?
        |
        +--> MFT / USN: were files copied or archived?
        |
        +--> Event logs / EDR: user session and process activity
        |
        +--> SRUM / proxy: outbound transfer context
```

## 15. Investigation Walkthrough

### Scenario

An organization suspects that sensitive project documents were copied to removable media.

### Step 1: Parse ShellBags

Observation:

- Alex's `UsrClass.dat` contains ShellBag entries for `E:\ClientData\Acquisition`.

Inference:

- Alex's user profile contains evidence of shell navigation to a folder on drive `E:`.

### Step 2: Identify Removable Device Context

Observation:

- USB artifacts show a removable device mounted as `E:` before the ShellBag timestamp.

Inference:

- The ShellBag path likely relates to that removable device session.

### Step 3: Look for File-Level Evidence

Observation:

- LNK files reference documents under `E:\ClientData\Acquisition`.
- Jump Lists show recent document access from Microsoft Word.

Inference:

- File-level interaction is supported more strongly than by ShellBags alone.

### Step 4: Look for Copy Evidence

Observation:

- MFT and USN records on the source system show archive creation shortly before removable drive browsing.
- EDR telemetry shows `explorer.exe` or another process writing files to `E:`.

Inference:

- Copy or staging activity is better supported when file system and process evidence align.

### Step 5: Write the Finding

Precise wording:

```text
ShellBag data from Alex's user profile contains folder navigation evidence for E:\ClientData\Acquisition. USB artifacts should be used to identify the removable device mounted as E:, and LNK, Jump List, MFT/USN, and EDR evidence should be used to determine whether specific files were opened or copied. ShellBags alone support folder-level shell interaction, not file copying by themselves.
```

## 16. ASCII Timeline

```text
01:42:10  USB artifact: removable device mounted as E:
01:45:22  ShellBag: E:\ClientData folder represented in Alex's hive
01:47:03  ShellBag: E:\ClientData\Acquisition represented
01:49:15  LNK / Jump List: document-level interaction if present
01:52:40  MFT / USN: file copy/archive evidence if present
```

## 17. Investigator's Mindset

ShellBags are excellent for folder-level leads. They should make the investigator ask sharper questions about files, devices, and transfers.

Ask:

- Which user hive contains the ShellBag entry?
- Is the path local, removable, network, archive, or virtual?
- What does the timestamp field actually represent?
- Is there LNK or Jump List evidence for file-level activity?
- Was removable media mounted at the same time?
- Do MFT or USN records show copy, archive, or delete activity?
- What evidence supports intent or transfer?

ShellBags show remembered places. They do not tell the whole journey.

## 18. Key Takeaways

- ShellBags record folder view state and shell navigation traces.
- They are stored in user registry hives, especially `NTUSER.DAT` and `UsrClass.dat`.
- They can preserve evidence of local, removable, network, and deleted folder paths.
- They do not prove specific file opening or copying by themselves.
- Timestamp interpretation requires parser and structure awareness.
- Strong ShellBag findings correlate with USB artifacts, LNK files, Jump Lists, MFT/USN, event logs, and EDR telemetry.

## 19. Review Questions

1. Why does Windows create ShellBag data?
2. Which user hives commonly contain ShellBag artifacts?
3. Why does folder navigation not prove file opening?
4. What artifacts would you use to test whether files were copied to USB?
5. Why is timestamp interpretation important in ShellBag analysis?

## 20. References

- Eric Zimmerman Tools, "ShellBags Explorer / SBECmd": https://ericzimmerman.github.io/
- Magnet Forensics, "Forensic Analysis of Windows Shellbags": https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags/
- Cyber Triage, "Shellbags Forensic Analysis 2026": https://www.cybertriage.com/blog/shellbags-forensic-analysis-2026/
- artifacts.help, "Registry - Shellbags": https://artefacts.help/windows_registry_shellbags.html
- GIAC, "Windows ShellBag Forensics in Depth": https://www.giac.org/paper/gcfa/9576/windows-shellbag-forensics-in-depth/128522
