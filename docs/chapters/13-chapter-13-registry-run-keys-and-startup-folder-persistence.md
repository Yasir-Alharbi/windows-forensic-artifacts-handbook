# Chapter 13: Registry Run Keys and Startup Folder Persistence

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why Windows supports Run, RunOnce, and Startup Folder autostart locations.
- Identify common per-user and machine-wide persistence locations.
- Interpret autorun entries as configured execution mechanisms, not automatic proof of successful execution.
- Correlate Run key evidence with logon events, process creation, MFT, USN, Prefetch, Amcache, and EDR telemetry.
- Recognize legitimate software noise and attacker abuse patterns.

## 2. Introduction

Registry Run keys and Startup folders are Windows autostart mechanisms. They allow programs to run when a user logs on. Legitimate software uses them for update agents, collaboration tools, endpoint security components, and user convenience. Attackers use them for persistence.

Common Run key locations include:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce
```

Common Startup folder locations include:

```text
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\
```

These artifacts are high-value because they show persistence configuration. They do not, by themselves, prove that the referenced program successfully ran.

## 3. Why Windows Created This Artifact

Windows supports Run and RunOnce keys so software can automatically launch at user logon. Microsoft documents that the Run key makes a program run each time a user logs on, while RunOnce runs one time and is then deleted.

Startup folders serve a similar user-facing purpose: shortcuts or executables placed there can launch during user logon.

This is normal operating system behavior. The same mechanism that starts legitimate software can be abused by adversaries.

## 4. Why Investigators Care

Investigators care because autorun entries are common persistence evidence.

| Investigative Need | Run Key / Startup Folder Contribution |
| --- | --- |
| Persistence discovery | Shows programs configured to run at logon. |
| User vs machine scope | HKCU is per-user; HKLM applies machine-wide. |
| Suspicious command discovery | Values may contain script, LOLBin, or encoded commands. |
| Timeline support | Registry key last write and file system timestamps support sequencing. |
| Malware staging | Referenced paths may point to user-writable directories. |
| Cleanup detection | RunOnce deletion or missing values may require hive transaction logs or backups. |
| ATT&CK mapping | Aligns with MITRE ATT&CK T1547.001. |

Autorun evidence often explains why malware reappeared after reboot or logon.

## 5. Internal Structure

Run and RunOnce entries are Registry values. The value name is often arbitrary, and the value data usually contains a command, executable path, script host invocation, or shortcut path.

Important distinctions:

| Location | Scope | Practical Meaning |
| --- | --- | --- |
| HKCU Run | Current user | Runs when that user logs on. |
| HKCU RunOnce | Current user | Intended to run once at that user's logon. |
| HKLM Run | Machine-wide | Runs for users logging on, subject to Windows behavior and permissions. |
| HKLM RunOnce | Machine-wide | Intended one-time execution, often setup-related. |
| Startup folder | User or all users | File-system based autostart through shell startup locations. |

Investigators should collect both Registry and file system evidence. A Run key points to a command; the referenced file may provide the strongest malware or tooling evidence.

## 6. Data Stored

Autorun analysis may expose:

- Registry hive path
- key path
- value name
- value data
- key last write time
- user SID or profile context
- referenced executable path
- command-line arguments
- script interpreter
- environment variables
- Startup folder file path
- LNK target metadata
- file system timestamps for referenced files

The value data matters more than the value name. Attackers commonly choose names that mimic legitimate software.

## 7. Acquisition Methods

Acquire the relevant Registry hives:

```text
C:\Windows\System32\config\SOFTWARE
C:\Windows\System32\config\SYSTEM
C:\Users\<user>\NTUSER.DAT
```

Collect transaction logs:

```text
SOFTWARE.LOG1
SOFTWARE.LOG2
SYSTEM.LOG1
SYSTEM.LOG2
NTUSER.DAT.LOG1
NTUSER.DAT.LOG2
```

Collect Startup folder contents from user and all-user locations.

Acquisition options:

- full disk image
- registry hive extraction
- triage collection
- Sysinternals Autoruns export
- EDR autorun inventory

Document:

- host name
- user profile and SID
- acquisition time in UTC
- hives and Startup folders collected
- parser or tool version
- whether transaction logs were included
- whether collection was live or offline

## 8. Interpretation

Autorun evidence shows configuration.

Example observation:

```text
Hive: C:\Users\alex\NTUSER.DAT
Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value name: OneDrive Update
Value data: C:\Users\alex\AppData\Roaming\update\winupdate.exe
Last write: 2026-07-14 03:26:04 UTC
```

Reasonable inference:

- Alex's user hive contains a Run key configured to launch `winupdate.exe` when Alex logs on.
- The value name appears to mimic legitimate update software.
- The referenced path is user-writable and suspicious.

Unsupported conclusion:

- "The persistence successfully executed after every logon."

To support execution, correlate with logon events, Prefetch, event 4688, EDR telemetry, Amcache, and file system activity.

## 9. Strengths

Run key and Startup folder artifacts have several strengths:

- Directly show configured autostart mechanisms.
- Simple to inspect and explain.
- Provide user or machine scope.
- Often include full command lines.
- Strong persistence evidence when suspicious.
- Easy to correlate with referenced files.
- Mapped to a well-known adversary technique.

These artifacts are often among the fastest ways to identify commodity malware persistence.

## 10. Weaknesses

Limitations include:

- They prove configuration, not successful execution.
- Legitimate software creates many autoruns.
- Values may be deleted before collection.
- RunOnce entries may remove themselves.
- Registry last write time is key-level, not value-level in normal Registry structure.
- Environment variables and relative paths require expansion.
- Startup folder LNK files require separate parsing.
- Attackers may use less common autostart mechanisms outside this chapter.

Autoruns are noisy. Suspiciousness comes from path, command, publisher, hash, timing, and context.

## 11. Common Mistakes

### Mistake 1: Treating Configuration As Execution

A Run key means the system is configured to run something at logon. Confirm actual execution separately.

### Mistake 2: Ignoring HKCU Scope

HKCU persistence applies to a specific user's hive. Identify the user SID and profile.

### Mistake 3: Ignoring WOW6432Node

32-bit software on 64-bit Windows may use redirected Registry paths.

### Mistake 4: Overtrusting Value Names

Attackers commonly use names resembling legitimate software. Inspect value data, file path, signature, hash, and behavior.

### Mistake 5: Ignoring Startup Folder LNK Details

A shortcut in Startup may hide its true target or arguments. Parse the LNK file.

## 12. Questions It Can Answer

Run key and Startup folder evidence can often help answer:

- Was a program configured to run at user logon?
- Was persistence per-user or machine-wide?
- What command or path was configured?
- Was the referenced path suspicious or user-writable?
- When did the key or Startup folder item change?
- Does persistence timing align with initial compromise or malware staging?

## 13. Questions It Cannot Answer

These artifacts cannot answer by themselves:

- Whether the program actually executed.
- Whether execution succeeded.
- Which process created the autorun value.
- Whether the referenced file was malicious.
- Whether the user intentionally configured it.
- Whether deleted RunOnce values existed without historical hive data or telemetry.

## 14. Evidence Correlation

Autorun evidence should be correlated with both configuration and execution artifacts.

| Correlating Artifact | Added Value |
| --- | --- |
| Event Logs 4624 | User logon context. |
| Event Logs 4688 | Process creation and command line if enabled. |
| Prefetch | Execution-related evidence for referenced executables. |
| Amcache / ShimCache | Program metadata and path context. |
| MFT / USN | Referenced file creation, modification, deletion. |
| LNK files | Startup shortcut target and arguments. |
| EDR telemetry | Process lineage, user session, file writes, Registry modifications. |
| Sysinternals Autoruns | Broad autostart enumeration for triage. |

### Correlation Map

```text
Run key: suspicious command configured
        |
        +--> MFT / USN: referenced file created before key change
        |
        +--> 4624: user logon after persistence creation
        |
        +--> Prefetch / 4688 / EDR: did it execute?
        |
        +--> Amcache / hash: file identity
        |
        +--> Network / SRUM: post-execution behavior
```

## 15. Investigation Walkthrough

### Scenario

An endpoint repeatedly reconnects to a suspicious command-and-control address after reboot.

### Step 1: Inspect Autoruns

Observation:

- HKCU Run in Alex's hive contains value `OneDrive Update`.
- Value data points to `C:\Users\alex\AppData\Roaming\update\winupdate.exe`.

Inference:

- The user hive contains per-user persistence configured at logon.

### Step 2: Check File System Timing

Observation:

- MFT and USN show `winupdate.exe` created shortly before the Run key last write time.

Inference:

- File staging and persistence configuration appear close in time.

### Step 3: Test Execution

Observation:

- Security 4624 shows Alex logged on after the Run key was created.
- Prefetch and EDR telemetry show `winupdate.exe` running shortly after logon.

Inference:

- Execution after logon is supported by independent artifacts.

### Step 4: Analyze Behavior

Observation:

- EDR and firewall logs show outbound connections from `winupdate.exe`.

Inference:

- The persistent executable likely generated the suspicious network behavior.

### Step 5: Write the Finding

Precise wording:

```text
Alex's HKCU Run key contains a suspicious autorun value named "OneDrive Update" pointing to C:\Users\alex\AppData\Roaming\update\winupdate.exe. MFT and USN records show the file was staged shortly before the Registry key changed. Subsequent logon and process telemetry support execution after user logon, and network telemetry links the process to suspicious outbound connections. The Run key proves persistence configuration; execution and behavior are supported by correlated artifacts.
```

## 16. ASCII Timeline

```text
03:22:11  MFT / USN: winupdate.exe created
03:26:04  Registry: HKCU Run key last write
08:02:18  4624: user logon
08:02:25  Prefetch / 4688 / EDR: winupdate.exe executes
08:02:40  Firewall / EDR: outbound connection
```

## 17. Investigator's Mindset

Autorun artifacts answer "what was configured to start?" They do not automatically answer "what ran successfully?"

Ask:

- Is the entry per-user or machine-wide?
- What command will Windows attempt to run?
- Is the path user-writable, hidden, remote, or unusual?
- Does the key last write align with file staging?
- Did a relevant user log on after the value was created?
- Is there Prefetch, 4688, or EDR evidence of execution?
- Is the entry legitimate software, attacker persistence, or an administrative tool?

Good persistence analysis separates configuration, trigger, execution, and behavior.

## 18. Key Takeaways

- Run and RunOnce keys configure programs to run at user logon.
- Startup folders provide file-system-based logon autostart behavior.
- HKCU is per-user; HKLM is machine-wide.
- Autorun values prove configuration, not successful execution.
- Registry key last write time is key-level, not value-level.
- Startup folder LNK files must be parsed for target and arguments.
- Strong findings correlate autoruns with logon events, execution artifacts, file system evidence, and EDR telemetry.

## 19. Review Questions

1. What is the difference between Run and RunOnce?
2. Why does HKCU vs HKLM scope matter?
3. Why does a Run key not prove successful execution?
4. What artifacts would you use to test whether a Run key executed after logon?
5. Why should Startup folder LNK files be parsed rather than only listed?

## 20. References

- Microsoft Learn, "Run and RunOnce Registry Keys": https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
- Microsoft Learn, "RunOnce Registry Key": https://learn.microsoft.com/en-us/windows-hardware/drivers/install/runonce-registry-key
- Microsoft Learn, "Autoruns for Windows": https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- MITRE ATT&CK, "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder": https://attack.mitre.org/techniques/T1547/001/
- persistence-info.github.io, "Run and RunOnce Registry Keys": https://persistence-info.github.io/Data/run.html
