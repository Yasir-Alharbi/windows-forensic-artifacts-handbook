# Chapter 12: Jump Lists

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why Windows creates Jump Lists.
- Distinguish AutomaticDestinations from CustomDestinations.
- Interpret Jump Lists as application-centric recent activity evidence.
- Use AppIDs, DestList entries, and embedded LNK data for investigation.
- Correlate Jump Lists with LNK files, ShellBags, MFT, USN, event logs, and user hives.

## 2. Introduction

Jump Lists are Windows shell artifacts that provide quick access to recent files, frequent locations, pinned items, and application tasks from the taskbar or Start Menu. They were introduced with Windows 7 and continue in later Windows versions.

For investigators, Jump Lists are valuable because they often connect a user profile, an application, and a target file or location. This makes them especially useful for document access, data staging, removable media, network share, and insider threat investigations.

Jump Lists are not universal logs of all file access. They are shell and application convenience artifacts. Their value depends on the application, user settings, Windows behavior, and whether the relevant files were retained.

## 3. Why Windows Created This Artifact

Windows created Jump Lists to improve user workflow. A user can right-click an application icon and quickly reopen recent documents, pinned files, frequent places, or application-specific tasks.

The forensic value comes from the data Windows and applications store to support that convenience. Recent and frequent targets, application identifiers, and embedded shortcut-like records can preserve useful activity traces.

## 4. Why Investigators Care

Jump Lists help answer an application-focused question: **which application had recent or frequent interaction with this file, folder, or location?**

| Investigative Need | Jump List Contribution |
| --- | --- |
| Document access leads | May show files recently opened by specific applications. |
| Application context | AppID can associate entries with Word, Excel, Explorer, browsers, and other apps. |
| User profile context | Jump Lists are stored under a user's profile. |
| Target metadata | Embedded LNK-like data may preserve paths and volume information. |
| Usage frequency | DestList data may include access count or ordering information. |
| Deleted target leads | Entries may persist after target files are removed. |
| Timeline support | Entry timestamps can support recent activity reconstruction. |

Jump Lists often strengthen cases where LNK files show a target path but the investigator needs application context.

## 5. Internal Structure

Jump Lists commonly appear in two forms.

| Type | Common Extension | Practical Meaning |
| --- | --- | --- |
| AutomaticDestinations | `.automaticDestinations-ms` | Created and maintained by Windows for recent and frequent application destinations. |
| CustomDestinations | `.customDestinations-ms` | Created by applications for custom tasks, pinned items, or app-specific destinations. |

Common locations:

```text
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\
```

AutomaticDestinations files are compound file structures and may contain a DestList stream plus embedded LNK-like streams. CustomDestinations files are commonly simpler collections of LNK-like records, though application behavior varies.

Each Jump List file name is associated with an AppID. Mapping the AppID to the application is critical.

## 6. Data Stored

Parsed Jump List output may include:

- AppID
- application name mapping
- target path
- entry ID
- access count
- last access or last modification style timestamps
- pin status
- hostname or machine identifier
- volume information
- embedded LNK metadata
- target file size
- target timestamps
- network path or removable volume context

Field names vary by parser. Read parser documentation and distinguish DestList metadata from embedded LNK target metadata.

## 7. Acquisition Methods

Acquire:

```text
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*
```

Also collect:

- user `NTUSER.DAT`
- user `UsrClass.dat`
- Recent Items LNK files
- relevant application data
- MFT and USN records for target paths

Document:

- user profile path
- collection time in UTC
- Jump List directories collected
- parser and version
- AppID mapping source
- whether source was live or offline

## 8. Interpretation

Jump List interpretation requires connecting user profile, AppID, and target.

Example observation:

```text
User profile: C:\Users\alex
Jump List AppID: Microsoft Excel mapping
Target: E:\Exports\client_list.xlsx
Last access-style timestamp: 2026-07-14 01:46:12 UTC
Access count: 1
```

Reasonable inference:

- Alex's profile contains Jump List evidence associating Microsoft Excel with `E:\Exports\client_list.xlsx`.
- This supports recent application-level interaction with that spreadsheet target.

Unsupported conclusion:

- "Alex copied the spreadsheet to USB."

The Jump List supports application interaction with a target path. Copying requires file system, USB, EDR, or other transfer evidence.

## 9. Strengths

Jump Lists have several strengths:

- User-profile-specific.
- Application-centric.
- Often include embedded LNK metadata.
- Can preserve deleted or missing target paths.
- Useful for document access investigations.
- Strong correlation with Recent Items, ShellBags, and USB artifacts.
- Can show frequency or ordering context in some structures.

Jump Lists are often better than generic file system evidence for showing which application was associated with a target.

## 10. Weaknesses

Jump Lists have important limitations:

- They are not complete file access logs.
- Application behavior varies.
- User settings can reduce or disable recent item tracking.
- AppID mapping may require parser or reference data.
- Timestamps can represent different concepts depending on structure.
- CustomDestinations are application-defined and can vary significantly.
- Missing entries do not prove no access occurred.

Treat Jump Lists as strong recent-activity evidence when present, not as complete history.

## 11. Common Mistakes

### Mistake 1: Ignoring the AppID

The AppID is central. A target path without application context loses much of the Jump List's value.

### Mistake 2: Confusing Embedded LNK Metadata With DestList Metadata

AutomaticDestinations can include both DestList records and embedded LNK-like streams. Know which timestamp or field you are using.

### Mistake 3: Treating Recent Activity As Copy Evidence

Jump Lists can support opening or application interaction, not copying by themselves.

### Mistake 4: Assuming Every Application Behaves the Same

Different applications populate Jump Lists differently.

### Mistake 5: Treating Access Count As a Perfect Counter

Access counts provide useful context but should not be treated as precise, complete historical counts without validation.

## 12. Questions It Can Answer

Jump Lists can often help answer:

- Which application is associated with a recent target?
- Which user profile contains the evidence?
- Did Word, Excel, Explorer, or another application reference this file?
- Was the target on removable media or a network share?
- Does application recent activity align with LNK, ShellBag, and file system evidence?

## 13. Questions It Cannot Answer

Jump Lists cannot answer by themselves:

- Whether a file was copied.
- Whether the user read the file contents.
- Whether the user intended the action.
- Whether every application access was recorded.
- Whether missing entries mean no access occurred.
- Whether target timestamps are independently trustworthy.

## 14. Evidence Correlation

Jump Lists are strongest when paired with shell, file, and device artifacts.

| Correlating Artifact | Added Value |
| --- | --- |
| LNK files | Target path, volume metadata, shortcut context. |
| ShellBags | Folder navigation context. |
| MFT / USN | File creation, modification, deletion, and copy patterns. |
| USB artifacts | Removable device identity and mount timeline. |
| Event Logs 4624 | User session context. |
| Event Logs 4688 / EDR | Application process creation and command line. |
| SRUM | Application network usage context. |
| Browser artifacts | Cloud upload/download context. |

### Correlation Map

```text
Jump List: application referenced target file
        |
        +--> LNK: target and volume metadata
        |
        +--> ShellBags: folder navigation
        |
        +--> MFT / USN: file movement or deletion
        |
        +--> USB artifacts: removable device mapping
        |
        +--> Event logs / EDR: user session and process context
```

## 15. Investigation Walkthrough

### Scenario

An organization suspects a spreadsheet was opened from a USB device before being uploaded to personal cloud storage.

### Step 1: Parse Jump Lists

Observation:

- Alex's AutomaticDestinations include an Excel AppID entry referencing `E:\Exports\client_list.xlsx`.

Inference:

- Alex's profile contains application-centric recent activity linking Excel to the spreadsheet path.

### Step 2: Compare LNK Evidence

Observation:

- Recent Items contains a LNK file referencing the same path and removable volume serial.

Inference:

- LNK evidence supports the target path and device context.

### Step 3: Check ShellBags

Observation:

- ShellBags show `E:\Exports` folder navigation.

Inference:

- Folder-level shell evidence supports browsing the destination folder.

### Step 4: Check Transfer Evidence

Observation:

- SRUM shows high outbound browser traffic after the spreadsheet activity.
- Browser history or proxy logs show access to cloud storage.

Inference:

- Upload remains a hypothesis until destination and content evidence are confirmed.

### Step 5: Write the Finding

Precise wording:

```text
Jump List evidence from Alex's profile associates Microsoft Excel with E:\Exports\client_list.xlsx. Recent Items LNK and ShellBag artifacts support interaction with the same removable-media path. These artifacts support application-level and shell-level interaction, but upload or copying conclusions require USB, MFT/USN, browser, proxy, SRUM, or EDR correlation.
```

## 16. ASCII Timeline

```text
01:42:10  USB artifact: device mounted as E:
01:45:22  ShellBag: E:\Exports folder represented
01:46:08  LNK: Recent Items shortcut references spreadsheet
01:46:12  Jump List: Excel AppID references spreadsheet
01:55:00  SRUM / browser / proxy: possible cloud upload context
```

## 17. Investigator's Mindset

Jump Lists are application-context artifacts. Use them to ask: "Which app was associated with this target, in this user's profile?"

Ask:

- Which user profile contains the Jump List?
- Which AppID is involved?
- Is the entry AutomaticDestinations or CustomDestinations?
- Which fields come from DestList versus embedded LNK data?
- Does the target path still exist?
- Do LNK files and ShellBags support the same path?
- Does process or network telemetry explain what happened next?

Jump Lists are powerful because they combine target and application context. Keep those contexts separate until correlation supports a conclusion.

## 18. Key Takeaways

- Jump Lists are Windows shell artifacts for recent, frequent, pinned, and application-specific destinations.
- AutomaticDestinations and CustomDestinations differ in structure and behavior.
- AppID mapping is critical for interpretation.
- Jump Lists can associate a user profile, application, and target path.
- They do not prove copying, content reading, or user intent by themselves.
- Strong findings correlate Jump Lists with LNK files, ShellBags, MFT/USN, USB artifacts, event logs, SRUM, and EDR telemetry.

## 19. Review Questions

1. What is the difference between AutomaticDestinations and CustomDestinations?
2. Why is the AppID important?
3. How are Jump Lists different from Recent Items LNK files?
4. Why do Jump Lists not prove copying by themselves?
5. Which artifacts would you use to investigate a Jump List reference to a USB path?

## 20. References

- Forensics Artifacts Knowledge Base, "Jump Lists": https://artifacts-kb.readthedocs.io/en/latest/sources/windows/JumpLists.html
- Eric Zimmerman, "JLECmd": https://github.com/EricZimmerman/JLECmd
- Eric Zimmerman Tools, "JumpList Explorer": https://ericzimmerman.github.io/
- SANS, "JLECmd": https://www.sans.org/tools/jlecmd/
- Cyber Triage, "What Is Jump List Cache?": https://www.cybertriage.com/blog/what-is-jump-list-cache/
- DFIR.pub, "Windows 10 Jump List and Link File Artifacts": https://dfir.pubpub.org/pub/wfuxlu9v
