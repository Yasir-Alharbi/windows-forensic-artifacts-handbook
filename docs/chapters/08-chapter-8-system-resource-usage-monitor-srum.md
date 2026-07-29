# Chapter 8: System Resource Usage Monitor (SRUM)

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why Windows maintains System Resource Usage Monitor (SRUM) data.
- Locate and acquire `SRUDB.dat` and supporting files.
- Interpret SRUM as resource-usage evidence, especially for application and network activity.
- Correlate SRUM with execution artifacts, event logs, MFT, USN, and network telemetry.
- Avoid overstating SRUM as packet capture, exact process telemetry, or proof of exfiltration by itself.

## 2. Introduction

System Resource Usage Monitor (SRUM) records resource usage data on modern Windows systems. It is commonly stored in an Extensible Storage Engine (ESE) database at:

```text
C:\Windows\System32\sru\SRUDB.dat
```

SRUM can provide evidence about application resource usage, network usage, connected networks, and related system activity. For investigators, it is especially useful when trying to determine whether a process or application transferred data during an incident window.

SRUM is not packet capture. It does not show full URLs, payloads, commands, or complete process lineage. Its value is in resource and usage context.

## 3. Why Windows Created This Artifact

Windows maintains SRUM to support diagnostics, resource monitoring, energy usage, and system behavior tracking. It helps the operating system understand how applications, services, and network interfaces consume resources over time.

The forensic value is incidental. Windows did not create SRUM to prove data theft. However, because SRUM records application and network usage data, investigators can use it to support or challenge hypotheses about execution, network activity, and potential exfiltration.

## 4. Why Investigators Care

SRUM helps answer questions that execution artifacts cannot answer alone.

| Investigative Need | SRUM Contribution |
| --- | --- |
| Application activity context | May show resource usage associated with applications. |
| Network usage magnitude | Can show bytes sent and received by application or interface context. |
| Exfiltration leads | Can support investigation of unusual outbound data volume. |
| Timeline support | Provides time-bucketed resource usage evidence. |
| Deleted executable support | May preserve usage records after a program is gone. |
| User context | Some parsed records may include security identifiers that map to users. |
| Network connectivity | May show networks the system connected to. |

SRUM is often most useful when an alert says "data left the host" and the investigator needs to identify which application or user context might be associated with that transfer.

## 5. Internal Structure

SRUM data is stored in an ESE database. Investigators usually interact with parsed output rather than raw database tables.

Important concepts:

| Concept | Practical Meaning |
| --- | --- |
| `SRUDB.dat` | Main SRUM database. |
| Transaction logs | Supporting ESE files that may contain recent changes. |
| SOFTWARE hive | Often used by parsers to resolve identifiers and application names. |
| Tables | Store categories such as application resource usage and network usage. |
| Time buckets | Records are often aggregated rather than continuous per-event logs. |

Parser output depends on the tool and available supporting files.

## 6. Data Stored

Parsed SRUM data may include:

- application or process name
- application identifier
- user security identifier (SID)
- timestamp or time bucket
- bytes sent
- bytes received
- interface type
- connected network information
- energy or resource usage values
- foreground/background related application context in some tables

The most common investigative focus is network data usage by application or user context.

## 7. Acquisition Methods

Acquire SRUM from:

```text
C:\Windows\System32\sru\SRUDB.dat
```

Also collect supporting files from the same directory, such as ESE logs and checkpoint files, when available:

```text
C:\Windows\System32\sru\SRU*.log
C:\Windows\System32\sru\SRU.chk
```

Collect the SOFTWARE hive as well because many parsers use it for resolution:

```text
C:\Windows\System32\config\SOFTWARE
```

Acquisition options:

- full disk image
- Volume Shadow Copy
- forensic triage tool
- endpoint response collection with locked-file support

Live copying can fail because the database may be locked. Use tools that can safely acquire locked files or collect from a forensic image.

Document:

- host name
- Windows version
- acquisition time in UTC
- database path
- supporting ESE files collected
- SOFTWARE hive collected
- parser and version
- whether the source was live or offline

## 8. Interpretation

SRUM is resource-usage evidence.

Example observation:

```text
Application: winupdate.exe
User SID: S-1-5-21-...
Time bucket: 2026-07-14 03:00 UTC
Bytes sent: 734,003,200
Bytes received: 12,582,912
```

Reasonable inference:

- Parsed SRUM data associates substantial outbound network usage with an application label resolving to `winupdate.exe` during the relevant time bucket.
- This supports investigation of possible data transfer by that application.

Unsupported conclusion:

- "winupdate.exe exfiltrated 700 MB of stolen data."

To support exfiltration, correlate with process telemetry, destination IPs, network logs, file access evidence, archive creation, command history, DLP logs, proxy logs, firewall logs, or packet capture.

## 9. Strengths

SRUM has several strengths:

- Provides application-level resource usage context.
- Can support network data transfer investigations.
- May retain useful data after event logs roll over.
- Helps identify unusual application network usage.
- Can include user SID context.
- Useful when EDR telemetry is missing or incomplete.
- Correlates well with execution and file system artifacts.

SRUM can be the artifact that turns "this program ran" into "this program also appears associated with unusual network volume."

## 10. Weaknesses

SRUM has important weaknesses:

- It is aggregated resource data, not detailed event telemetry.
- It does not show full process lineage.
- It does not show command line.
- It does not show destination domains or URLs by itself.
- It does not prove file content was exfiltrated.
- Parser resolution may depend on supporting hives.
- Time buckets may be coarser than event logs.
- Database acquisition can be complicated on live systems.

SRUM supports hypotheses about activity magnitude and timing. It does not replace network forensics.

## 11. Common Mistakes

### Mistake 1: Treating Bytes Sent As Proven Exfiltration

Outbound bytes can represent many things: update traffic, backup, sync, legitimate uploads, malware command and control, or exfiltration. Content and destination context are required.

### Mistake 2: Expecting Packet-Level Detail

SRUM is not packet capture. It does not provide payloads, full URLs, or complete connection records.

### Mistake 3: Ignoring Time Bucket Granularity

SRUM timing may be aggregated. Do not force second-level precision where the artifact does not support it.

### Mistake 4: Parsing Without Supporting Hives

Without the SOFTWARE hive or related context, application and identifier resolution may be weaker.

### Mistake 5: Ignoring Legitimate High-Volume Applications

Browsers, backup clients, cloud sync tools, update services, and collaboration apps can generate large traffic volumes. Baseline and context matter.

## 12. Questions It Can Answer

SRUM can often help answer:

- Which applications show network usage during the incident window?
- Which user SID is associated with resource usage records?
- Was there unusual outbound data volume?
- Did a suspicious executable have resource or network usage?
- What networks or interfaces were involved?
- Does resource usage align with execution artifacts and alerts?

## 13. Questions It Cannot Answer

SRUM cannot answer by itself:

- What exact data was transferred.
- Which remote URL or domain received the data.
- Whether the transfer was malicious.
- Which parent process launched the application.
- What command line was used.
- Whether a user intentionally caused the transfer.
- Whether no SRUM record means no network activity occurred.

## 14. Evidence Correlation

SRUM is strongest when combined with network and endpoint telemetry.

| Correlating Artifact | Added Value |
| --- | --- |
| Prefetch | Execution-related timing for the application. |
| Amcache / ShimCache | Program path and metadata context. |
| Event Logs 4688 | Process creation and command line if enabled. |
| MFT / USN | File staging, archive creation, deletion, or cleanup. |
| Browser artifacts | Upload/download or web session context. |
| Firewall / proxy logs | Destination IP, domain, URL, and policy action. |
| EDR telemetry | Process lineage, network connections, hash, user session. |
| Memory forensics | Active connections, injected code, process context. |

### Correlation Map

```text
SRUM: high outbound bytes for suspicious application
        |
        +--> Prefetch / 4688: did the application run then?
        |
        +--> MFT / USN: were archives or sensitive files staged?
        |
        +--> Proxy / firewall: where did the traffic go?
        |
        +--> EDR: process lineage, command line, destination IP
        |
        +--> DLP / server logs: what content left?
```

## 15. Investigation Walkthrough

### Scenario

A workstation triggers an alert for possible data exfiltration. Network monitoring shows a large outbound transfer, but endpoint process telemetry is incomplete.

### Step 1: Parse SRUM

Observation:

- SRUM shows high outbound bytes associated with `rclone.exe` during the alert window.
- The user SID resolves to `CORP\alex`.

Inference:

- SRUM supports that an application identified as `rclone.exe` was associated with significant outbound network usage in that time period.

### Step 2: Confirm Execution

Observation:

- Prefetch contains `RCLONE.EXE-...pf`.
- Event 4688 is unavailable, but Amcache contains path metadata.

Inference:

- Execution-related artifacts support that `rclone.exe` ran on the host.

### Step 3: Check File Staging

Observation:

- MFT and USN show creation of `C:\Users\alex\AppData\Local\Temp\data.zip` shortly before SRUM network usage.

Inference:

- File system evidence supports possible staging before outbound transfer.

### Step 4: Identify Destination

Observation:

- Firewall or proxy logs show outbound traffic to a cloud storage endpoint from the host during the same window.

Inference:

- Network telemetry provides destination context that SRUM lacks.

### Step 5: Write the Finding

Precise wording:

```text
SRUM records show substantial outbound network usage associated with rclone.exe under the user context CORP\alex during the alert window. Prefetch and Amcache support execution-related activity for rclone.exe, and MFT/USN records show a temporary archive created shortly before the transfer. Firewall or proxy logs are required to confirm destination and strengthen any exfiltration conclusion.
```

## 16. ASCII Timeline

```text
02:54:12  MFT / USN: data.zip created in user Temp
02:56:00  Prefetch: RCLONE.EXE execution-related timestamp
03:00:00  SRUM: high outbound bytes in application time bucket
03:02:15  Firewall: outbound session to cloud storage endpoint
03:08:40  USN: data.zip deleted
```

The SRUM bucket supports timing and magnitude. Destination and content require other logs.

## 17. Investigator's Mindset

Use SRUM to ask better network and process questions.

Ask:

- Which application is associated with the usage?
- Which user SID is associated with the record?
- How precise is the time bucket?
- Is the volume unusual for this application and host?
- Does execution evidence support the application ran then?
- Are there staged archives or sensitive files nearby in time?
- What network logs can identify the destination?
- What evidence would prove content, not just volume?

SRUM is a correlation amplifier. It rarely stands alone.

## 18. Key Takeaways

- SRUM stores resource usage data in `C:\Windows\System32\sru\SRUDB.dat`.
- It is useful for application and network usage analysis.
- SRUM can support exfiltration investigations but does not prove exfiltration by itself.
- It does not provide packet payloads, full URLs, command lines, or complete process lineage.
- Collect supporting ESE files and the SOFTWARE hive when possible.
- Strong SRUM findings correlate with execution artifacts, file staging evidence, firewall/proxy logs, and EDR telemetry.

## 19. Review Questions

1. What kind of evidence does SRUM provide?
2. Why is SRUM not equivalent to packet capture?
3. Why should the SOFTWARE hive be collected with `SRUDB.dat`?
4. What artifacts would you use to test an exfiltration hypothesis based on SRUM?
5. Why should bytes sent be treated as a lead rather than proof of data theft?

## 20. References

- Eric Zimmerman, "SrumECmd": https://github.com/EricZimmerman/Srum
- Forensics Artifacts Knowledge Base, "System Resource Usage Monitor": https://artifacts-kb.readthedocs.io/en/latest/sources/windows/SystemResourceUsageMonitor.html
- libyal, "System Resource Usage Monitor (SRUM) database": https://github.com/libyal/esedb-kb/blob/main/documentation/System%20Resource%20Usage%20Monitor%20%28SRUM%29.asciidoc
- Magnet Forensics, "SRUM: Forensic Analysis of Windows System Resource Utilization Monitor": https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/
- artifacts.help, "System Resource Usage Monitor (SRUM)": https://artefacts.help/windows_srum.html
