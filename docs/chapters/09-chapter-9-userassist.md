# Chapter 9: UserAssist

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain what UserAssist records and why Windows maintains it.
- Locate UserAssist data in a user's `NTUSER.DAT` hive.
- Interpret UserAssist as per-user Explorer shell activity evidence.
- Decode the investigative meaning of ROT13-obfuscated value names.
- Correlate UserAssist with Prefetch, Amcache, event logs, LNK files, Jump Lists, and MFT evidence.

## 2. Introduction

UserAssist is a Windows Registry artifact associated with the Explorer shell. It records information about programs and shortcuts launched through graphical user interface (GUI) interactions.

UserAssist data is stored per user, usually in that user's `NTUSER.DAT` hive under:

```text
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```

For investigators, UserAssist is valuable because it can connect application activity to a specific user profile. That makes it different from system-wide artifacts such as Prefetch, Amcache, and ShimCache.

UserAssist is not a complete execution log. It is strongest for GUI-associated activity. Command-line execution, services, scheduled tasks, remote execution, and many malware execution paths may not produce UserAssist entries.

## 3. Why Windows Created This Artifact

Windows uses UserAssist to support Explorer shell features such as tracking frequently used applications and improving user experience. The artifact reflects application use from the perspective of the user shell.

The forensic value is incidental. Windows records these values for usability and shell behavior, not for incident response.

## 4. Why Investigators Care

UserAssist can help answer a question that system-wide execution artifacts often cannot: **which user profile contains evidence of GUI-associated program activity?**

| Investigative Need | UserAssist Contribution |
| --- | --- |
| User context | Stored in a specific user's `NTUSER.DAT`. |
| GUI activity | Supports activity launched through Explorer or shortcuts. |
| Program frequency | May include run count values. |
| Last run context | May include last execution time. |
| Shortcut use | Can show `.lnk`-associated entries. |
| Timeline support | Helps align user activity with logon and execution evidence. |

This artifact is especially useful when an investigator must distinguish automated execution from interactive user-shell activity.

## 5. Internal Structure

UserAssist entries are located beneath GUID-named subkeys. Values are commonly ROT13-obfuscated. ROT13 is not encryption; it is a simple letter substitution where each alphabetic character is rotated by 13 positions.

Example:

```text
P:\Jvaqbjf\Flfgrz32\pnyr.exe
```

ROT13-decoded:

```text
C:\Windows\System32\calc.exe
```

Parsed UserAssist output commonly resolves:

- decoded path or shortcut
- run count
- focus count or focus time in some versions
- last run timestamp
- GUID category

Field availability varies by Windows version and parser.

## 6. Data Stored

Parsed UserAssist data may include:

| Field | Investigative Use |
| --- | --- |
| Decoded path | Identifies executable or shortcut. |
| Run count | Supports frequency of GUI-associated launches. |
| Last run time | Places activity in time. |
| User hive | Associates activity with a user profile. |
| Shortcut indicator | May show activity through a `.lnk` file. |
| Focus values | Can support user interaction context in some versions. |

The user hive matters. UserAssist from `C:\Users\alex\NTUSER.DAT` is evidence from Alex's profile hive, not a system-wide record.

## 7. Acquisition Methods

Acquire the user's registry hive:

```text
C:\Users\<user>\NTUSER.DAT
```

Also collect hive transaction logs when available:

```text
C:\Users\<user>\NTUSER.DAT.LOG1
C:\Users\<user>\NTUSER.DAT.LOG2
```

Acquisition options include:

- full disk image
- user profile triage collection
- endpoint response file retrieval
- live registry export, with caution

Document:

- user profile path
- user SID if known
- collection time in UTC
- hive path and hash
- whether transaction logs were collected
- parser and version
- whether the system was live or offline

## 8. Interpretation

UserAssist evidence supports GUI-shell-associated program or shortcut activity for a user profile.

Example observation:

```text
Hive: C:\Users\alex\NTUSER.DAT
Decoded UserAssist value: C:\Users\alex\Downloads\AnyDesk.exe
Last run: 2026-07-14 02:41:10 UTC
Run count: 1
```

Reasonable inference:

- Alex's user hive contains UserAssist evidence associated with GUI launch activity for `AnyDesk.exe`.
- The entry supports that the program was launched through Explorer/shell-associated interaction around the recorded time.

Unsupported conclusion:

- "Alex knowingly installed remote access software."

The artifact is per-user, but it does not prove intent. The account could have been compromised, the program could have been launched by another person using the session, or activity may have occurred under remote control.

## 9. Strengths

UserAssist has several strengths:

- Per-user context.
- Useful for GUI-associated launches.
- Can preserve last run time and count.
- Helpful for distinguishing interactive shell activity from background execution.
- Correlates well with LNK files, Jump Lists, Prefetch, and event logs.
- ROT13 values are easily decoded by forensic tools.

UserAssist is particularly valuable when a suspicious tool was launched from Downloads, Desktop, or another user-accessible location.

## 10. Weaknesses

UserAssist has important limitations:

- It is not a complete execution log.
- Command-line, service, scheduled task, and remote execution may not appear.
- It does not prove the human user's intent.
- Run counts can be misunderstood.
- Registry hives can be affected by transaction logs and live state.
- Deleted or missing entries do not prove no execution occurred.
- Malware can avoid Explorer-shell launch paths.

Use UserAssist as user-context evidence, not as the only proof of execution.

## 11. Common Mistakes

### Mistake 1: Treating UserAssist As All Execution

UserAssist is strongest for Explorer/GUI-associated activity. It misses many execution paths.

### Mistake 2: Confusing User Profile With Human Intent

An entry in Alex's hive means the evidence is associated with Alex's user profile. It does not prove Alex personally intended the action.

### Mistake 3: Ignoring ROT13 Decoding

Raw value names may look strange until decoded. Use a parser or decode carefully.

### Mistake 4: Ignoring Hive Transaction Logs

Live or recently changed registry data may require transaction logs for the most complete view.

### Mistake 5: Overtrusting Run Counts

Run counts provide useful context but should not be treated as perfect historical counters.

## 12. Questions It Can Answer

UserAssist can often help answer:

- Does a user's hive show GUI-associated activity for this program?
- When was the program last recorded in UserAssist?
- Was a shortcut or executable path involved?
- Which user profile contains the evidence?
- Does user-shell activity align with logon, Prefetch, and file system evidence?

## 13. Questions It Cannot Answer

UserAssist cannot answer by itself:

- Whether all executions of the program occurred.
- Whether a process ran from command line or service context.
- Whether the user intentionally launched the program.
- What command line was used.
- Which parent process launched it.
- Whether the file was malicious.
- Whether missing UserAssist means no execution.

## 14. Evidence Correlation

UserAssist is strongest when correlated with both user activity and execution artifacts.

| Correlating Artifact | Added Value |
| --- | --- |
| Prefetch | Execution-related evidence and run timing. |
| Amcache | Path, metadata, and hash context. |
| Event Logs 4624 | User logon session context. |
| Event Logs 4688 | Process creation and command line if enabled. |
| LNK files | Shortcut target, timestamps, and file interaction. |
| Jump Lists | Recent application and document activity. |
| MFT / USN | File creation, movement, and deletion. |
| Browser artifacts | Download origin and timing. |
| EDR telemetry | Process lineage, user session, command line, and network activity. |

### Correlation Map

```text
UserAssist: user's hive records GUI-associated program activity
        |
        +--> 4624: was the user logged on?
        |
        +--> Prefetch: did Windows record execution-related evidence?
        |
        +--> LNK / Jump List: did the shell record shortcut or recent use?
        |
        +--> MFT / USN: when did the executable appear?
        |
        +--> 4688 / EDR: parent process, command line, user session
```

## 15. Investigation Walkthrough

### Scenario

An analyst is investigating unauthorized remote access software on a workstation.

### Step 1: Parse UserAssist

Observation:

- `C:\Users\alex\NTUSER.DAT` contains a UserAssist entry for `C:\Users\alex\Downloads\AnyDesk.exe`.
- Last run time is `2026-07-14 02:41:10 UTC`.

Inference:

- Alex's profile contains evidence of GUI-associated activity for `AnyDesk.exe`.

### Step 2: Correlate Logon Context

Observation:

- Security 4624 shows an interactive or remote interactive logon for `alex` before the UserAssist timestamp.

Inference:

- The user session context aligns with the UserAssist activity.

### Step 3: Correlate Execution

Observation:

- Prefetch contains `ANYDESK.EXE-...pf`.
- Event 4688 or EDR telemetry shows process creation.

Inference:

- Execution is supported by multiple artifacts.

### Step 4: Correlate Origin

Observation:

- Browser history shows a download of `AnyDesk.exe` before the UserAssist timestamp.
- MFT and USN show file creation in Downloads.

Inference:

- Browser and file system evidence support how the executable arrived, if the source and timing align.

### Step 5: Write the Finding

Precise wording:

```text
UserAssist data from C:\Users\alex\NTUSER.DAT records GUI-associated activity for C:\Users\alex\Downloads\AnyDesk.exe at 2026-07-14 02:41:10 UTC. Prefetch and process telemetry support execution, while browser and file system artifacts should be used to determine how the file arrived. The artifact associates the activity with Alex's user profile but does not prove Alex's intent.
```

## 16. ASCII Timeline

```text
02:37:44  Browser history: AnyDesk.exe download candidate
02:38:01  MFT / USN: AnyDesk.exe created in Downloads
02:40:50  4624: user logon/session context
02:41:10  UserAssist: GUI-associated activity in Alex's hive
02:41:12  Prefetch / 4688: execution-related evidence
```

## 17. Investigator's Mindset

UserAssist is about user-contextual shell activity. It is powerful because it is per-user, but it still does not prove human intent by itself.

Ask:

- Which user's hive contains the entry?
- Was the value decoded correctly?
- Is this GUI-shell-associated activity or another execution path?
- Was the user logged on?
- Do Prefetch or event logs support execution?
- Do LNK files or Jump Lists support user interaction?
- Could remote control, malware, or another user in the session explain the activity?

The right claim is usually narrower and stronger than "the user ran it."

## 18. Key Takeaways

- UserAssist is stored per user in `NTUSER.DAT`.
- It records Explorer/GUI-associated application or shortcut activity.
- Value names are commonly ROT13-obfuscated.
- UserAssist can provide last run and count context.
- It does not capture all execution paths.
- It associates evidence with a user profile, not necessarily human intent.
- Strong findings correlate UserAssist with logon events, Prefetch, LNK files, Jump Lists, MFT/USN, and EDR telemetry.

## 19. Review Questions

1. Where is UserAssist stored?
2. Why is UserAssist useful for user attribution?
3. Why does UserAssist not prove human intent?
4. What execution paths may not create UserAssist evidence?
5. Which artifacts would you use to strengthen a UserAssist finding?

## 20. References

- Eric Zimmerman, "RegistryPlugins": https://github.com/EricZimmerman/RegistryPlugins
- Eric Zimmerman Tools, "RECmd / Registry Explorer": https://ericzimmerman.github.io/
- Magnet Forensics, "UserAssist Forensic Artifacts": https://www.magnetforensics.com/blog/artifact-profile-userassist/
- Kaspersky Securelist, "What is UserAssist and how to use it in IR activities?": https://securelist.com/userassist-artifact-forensic-value-for-incident-response/116911/
- Cyber Triage, "UserAssist Forensics 2026": https://www.cybertriage.com/blog/userassist-forensics-2026/
