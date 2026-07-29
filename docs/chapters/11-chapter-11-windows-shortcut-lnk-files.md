# Chapter 11: Windows Shortcut (LNK) Files

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why Windows creates Shell Link (`.lnk`) files.
- Identify common locations where LNK files appear.
- Interpret target paths, timestamps, volume metadata, and tracker information.
- Use LNK files to support user interaction, removable media, network path, and file access investigations.
- Correlate LNK evidence with ShellBags, Jump Lists, MFT, USN, event logs, and USB artifacts.

## 2. Introduction

Windows shortcut files, commonly called LNK files, are Shell Link files that point to another object such as a file, folder, executable, network location, or control panel item. They are used throughout Windows for Start Menu shortcuts, desktop shortcuts, Recent Items, application links, and user convenience.

For investigators, LNK files are valuable because they can preserve information about a target file or folder even after the target no longer exists. A LNK file may include the target path, timestamps, file size, drive information, volume serial number, network path, and distributed link tracking data.

LNK files are especially useful in investigations involving:

- opened documents
- removable media
- network shares
- downloaded files
- staged tools
- deleted targets
- user activity timelines

## 3. Why Windows Created This Artifact

Windows created Shell Links to let users and applications reference objects conveniently without duplicating the original file or folder. A shortcut can be placed on the Desktop, Start Menu, taskbar, or recent-items area while pointing to a target elsewhere.

Microsoft's Shell Link Binary File Format specification describes the structure used to store information that can locate and identify the link target.

The forensic value comes from this locator information. To help Windows resolve a target, the shortcut may preserve metadata that is extremely useful during investigation.

## 4. Why Investigators Care

LNK files can connect user activity to files, folders, volumes, and network paths.

| Investigative Need | LNK Contribution |
| --- | --- |
| File interaction leads | Recent Items shortcuts can indicate user or shell interaction with a target. |
| Deleted target recovery | Target metadata may persist after the target is gone. |
| Removable media context | Volume serial, drive type, and path can identify external devices. |
| Network share context | UNC paths may show remote target access. |
| Timeline anchors | LNK file timestamps and target timestamps support sequencing. |
| Target identity | File size, timestamps, and path help distinguish same-named files. |
| User profile context | LNK files often reside in user-specific locations. |

LNK files are one of the strongest user-activity artifacts when interpreted with proper context.

## 5. Internal Structure

Investigators do not need to manually parse the binary format, but several components matter.

| Component | Practical Meaning |
| --- | --- |
| Shell Link Header | Contains flags, file attributes, and target timestamps. |
| LinkTargetIDList | May store shell item path information. |
| LinkInfo | May store local path, network path, volume, and drive information. |
| StringData | May store relative path, working directory, arguments, icon path, or name. |
| ExtraData | May store tracker, environment, console, and other blocks. |

Different LNK files contain different blocks depending on how they were created and what Windows needed to store.

## 6. Data Stored

Parsed LNK output may include:

- target path
- local base path
- relative path
- command-line arguments
- working directory
- icon path
- target created, modified, and accessed timestamps
- LNK file created, modified, and accessed timestamps from the file system
- target file size
- target file attributes
- drive type
- drive serial number
- volume label
- network share path
- machine identifier
- distributed link tracking identifiers

Command-line arguments are particularly important when the LNK launches an executable. Malicious shortcuts often abuse arguments to launch scripts, download payloads, or execute commands through trusted binaries.

## 7. Acquisition Methods

Common LNK locations include:

```text
C:\Users\<user>\Desktop\
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\
C:\ProgramData\Microsoft\Windows\Start Menu\
```

Also collect LNK files from:

- Downloads
- extracted archives
- suspicious staging directories
- removable media images
- malware delivery folders
- email attachment extraction locations

Acquisition options include:

- full disk image
- user profile triage collection
- targeted collection of Recent Items and Desktop
- EDR file retrieval

Document:

- source path
- user profile
- collection time in UTC
- tool and parser version
- original LNK file timestamps
- hash of each LNK file when possible

## 8. Interpretation

LNK interpretation depends on location, target, timestamps, and creation context.

Example observation:

```text
LNK path: C:\Users\alex\AppData\Roaming\Microsoft\Windows\Recent\budget.xlsx.lnk
Target path: E:\Finance\budget.xlsx
Drive serial: 1234-ABCD
Target modified: 2026-07-14 01:31:08 UTC
```

Reasonable inference:

- Alex's profile contains a Recent Items shortcut pointing to `E:\Finance\budget.xlsx`.
- The evidence supports shell or application interaction with a file on a volume mounted as `E:`.
- The drive serial can help correlate the target to removable media evidence.

Unsupported conclusion:

- "Alex copied the file to USB."

The LNK supports interaction with a target path. Copy activity requires file system, USB, EDR, or other transfer evidence.

## 9. Strengths

LNK files have several strengths:

- Often user-profile-specific.
- Can preserve target path after deletion or device removal.
- May include removable drive metadata.
- Can include network share paths.
- Useful for document and shortcut interaction analysis.
- May reveal command-line arguments.
- Strong correlation with Jump Lists, ShellBags, and USB artifacts.

LNK files are often decisive for proving that a user profile had interaction with a specific file path.

## 10. Weaknesses

LNK limitations include:

- They do not always prove file content was read.
- They do not prove files were copied.
- They can be created by applications, installers, malware, or shell activity.
- Target timestamps are metadata about the target, not necessarily interaction times.
- LNK file timestamps can be affected by copying or preservation errors.
- Missing LNK files do not prove no interaction occurred.
- Malicious LNK files may contain deceptive names and command lines.

Interpret the LNK's location and creation mechanism before making a conclusion.

## 11. Common Mistakes

### Mistake 1: Treating Target Timestamps As LNK Creation Times

The target created, modified, and accessed timestamps describe the target metadata stored in the shortcut. They are not automatically the shortcut creation time.

### Mistake 2: Treating Recent Items As Copy Evidence

A Recent Items LNK can support file interaction. It does not prove a copy operation.

### Mistake 3: Ignoring Command-Line Arguments

Malicious LNK files may point to a trusted executable but include dangerous arguments. Always parse arguments and working directory.

### Mistake 4: Ignoring Volume Metadata

Drive serial and volume label can be critical for removable media correlation.

### Mistake 5: Assuming the Target Still Exists

LNK files may outlive their targets. Use MFT, USN, backups, or device images to test target existence.

## 12. Questions It Can Answer

LNK files can often help answer:

- What target did this shortcut reference?
- Which user profile contained the shortcut?
- Did a Recent Items shortcut reference this document or folder?
- What volume or network path was associated with the target?
- Did the shortcut include command-line arguments?
- Does the target metadata align with other artifacts?

## 13. Questions It Cannot Answer

LNK files cannot answer by themselves:

- Whether a user read the file contents.
- Whether a file was copied.
- Whether the target was malicious.
- Whether the user intentionally created the shortcut.
- Whether missing LNK files mean no access occurred.
- Whether target timestamps are trustworthy without correlation.

## 14. Evidence Correlation

LNK evidence is strongest when paired with user and file system artifacts.

| Correlating Artifact | Added Value |
| --- | --- |
| ShellBags | Folder navigation and view-state context. |
| Jump Lists | Application-specific recent file activity. |
| MFT / USN | Target existence, creation, modification, deletion, copy patterns. |
| USB artifacts | Device identity, mount time, drive letter, serial number. |
| Event Logs | Logon session and process activity context. |
| Prefetch / Amcache | Execution evidence for shortcut-launched programs. |
| Browser artifacts | Download origin for LNK-delivered malware. |
| EDR telemetry | Process lineage, command line, file writes, network activity. |

### Correlation Map

```text
LNK: target path and metadata
        |
        +--> ShellBags: folder navigation context
        |
        +--> Jump Lists: application recent-file context
        |
        +--> MFT / USN: target file existence and changes
        |
        +--> USB artifacts: removable media identification
        |
        +--> EDR / 4688: shortcut-launched process behavior
```

## 15. Investigation Walkthrough

### Scenario

An analyst investigates possible data removal to USB media.

### Step 1: Parse Recent Items

Observation:

- `C:\Users\alex\AppData\Roaming\Microsoft\Windows\Recent\client_list.xlsx.lnk` points to `E:\Exports\client_list.xlsx`.
- The LNK contains drive serial `1234-ABCD`.

Inference:

- Alex's profile contains a Recent Items shortcut referencing a spreadsheet on drive `E:`.

### Step 2: Correlate USB Device Artifacts

Observation:

- USB artifacts show a removable device with matching volume serial mounted as `E:` before the LNK timestamp.

Inference:

- The shortcut likely relates to that removable media session.

### Step 3: Look For Source File Evidence

Observation:

- MFT and USN show `client_list.xlsx` was accessed or copied from a corporate project folder before the removable-media interaction.

Inference:

- File system evidence may support staging or copying, depending on the exact records.

### Step 4: Check Application Context

Observation:

- Jump Lists for Excel reference the same file path.

Inference:

- Application recent-file evidence supports interaction with the spreadsheet.

### Step 5: Write the Finding

Precise wording:

```text
Alex's Recent Items contains a LNK file referencing E:\Exports\client_list.xlsx with removable-volume metadata. USB artifacts should be used to identify the device mounted as E:, and MFT/USN plus Jump List evidence should be used to determine whether the file was copied or opened. The LNK strongly supports user-profile-associated reference to the target path but does not prove copying by itself.
```

## 16. ASCII Timeline

```text
01:42:10  USB artifact: removable device mounted as E:
01:45:22  ShellBag: E:\Exports folder represented
01:46:08  LNK: Recent Items shortcut references E:\Exports\client_list.xlsx
01:46:12  Jump List: Excel recent-file entry if present
01:48:30  MFT / USN: source or destination file activity if present
```

## 17. Investigator's Mindset

LNK files are rich because they preserve target context. The investigator's job is to separate target metadata, shortcut metadata, and user inference.

Ask:

- Where was the LNK found?
- Which user profile does it belong to?
- What target path and arguments does it contain?
- Are target timestamps being confused with LNK timestamps?
- Does volume metadata match a removable device?
- Do Jump Lists or ShellBags support interaction?
- Do MFT and USN records support copying, deletion, or movement?

Use LNK files to anchor user-path evidence, then correlate outward.

## 18. Key Takeaways

- LNK files are Windows Shell Link shortcut files.
- They can preserve target paths, timestamps, volume metadata, network paths, and arguments.
- Recent Items LNK files are strong user-profile-associated leads.
- LNK files do not prove file copying or content reading by themselves.
- Target timestamps and shortcut file timestamps are different evidence.
- Malicious LNK files may hide dangerous command-line arguments.
- Strong findings correlate LNK files with ShellBags, Jump Lists, MFT/USN, USB artifacts, event logs, and EDR telemetry.

## 19. Review Questions

1. Why does Windows create LNK files?
2. What is the difference between target timestamps and LNK file timestamps?
3. Why are command-line arguments important in malicious LNK analysis?
4. How can LNK volume metadata support USB investigations?
5. Which artifacts would you use to test whether a LNK target was copied?

## 20. References

- Microsoft, "[MS-SHLLINK]: Shell Link (.LNK) Binary File Format": https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/99ac930d-9419-4254-b6c9-0f909af95c13
- Eric Zimmerman, "LECmd": https://github.com/EricZimmerman/LECmd
- SANS, "LECmd": https://www.sans.org/tools/lecmd/
- Forensics Wiki, "LNK": https://forensics.wiki/lnk/
- Cyber Triage, "LNK File Forensics 2026": https://www.cybertriage.com/blog/lnk-file-forensics-2026/
