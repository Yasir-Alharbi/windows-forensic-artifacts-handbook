# Chapter 22: Timeline Building and Evidence Correlation

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why timelines are central to Windows incident reconstruction.
- Build targeted and broad timelines from multiple artifact sources.
- Distinguish event time, artifact time, parser time, and inference time.
- Correlate artifacts without overstating causation.
- Write findings that separate observation, evidence, inference, assumption, and conclusion.

## 2. Introduction

Timeline analysis is the discipline of arranging evidence in time so an investigator can reconstruct what happened. A good timeline does more than sort timestamps. It explains relationships between artifacts: file creation, logon, process execution, persistence creation, network activity, detection, cleanup, and recovery actions.

This handbook has covered many artifact types individually. Timeline building is where those artifacts become an investigation.

The central question is:

**What sequence of observed facts best explains the incident, and what evidence supports each step?**

## 3. Why Windows Created This Artifact

Windows did not create one single "timeline artifact." Instead, many Windows components record timestamps because they need to manage files, sessions, configuration, logs, application state, and security events.

Timeline tools such as Plaso/log2timeline collect timestamped events from many sources and normalize them into a single analysis view. Timesketch and similar tools help investigators search, annotate, and collaborate on timelines.

The investigator's job is to turn many timestamped records into a defensible reconstruction.

## 4. Why Investigators Care

Timelines help investigators answer incident questions that individual artifacts cannot answer alone.

| Investigative Need | Timeline Contribution |
| --- | --- |
| Initial access | Shows first suspicious evidence and preceding activity. |
| Execution | Correlates file creation, process execution, and program artifacts. |
| Persistence | Places Run keys, services, tasks, and WMI changes in sequence. |
| Lateral movement | Links logons, remote execution, and file staging across hosts. |
| Exfiltration | Aligns archive creation, browser/cloud activity, SRUM, and network logs. |
| Cleanup | Shows deletion, log clearing, and security tool tampering. |
| Scope | Compares patterns across hosts and accounts. |

Timelines make the investigation testable.

## 5. Internal Structure

Think of a timeline as structured rows plus analyst interpretation.

Useful fields include:

| Field | Purpose |
| --- | --- |
| Timestamp UTC | Normalized event time. |
| Source host | System where evidence originated. |
| Artifact source | MFT, USN, Event Log, browser, EDR, memory, and so on. |
| Event type | File created, process started, logon, task registered, detection. |
| Description | Human-readable event summary. |
| Path/account/process | Key entity involved. |
| Confidence | High, medium, low, or explained in text. |
| Notes | Assumptions, parser caveats, and correlation links. |

Two timeline types matter:

- **Broad timeline**: many artifact sources, useful for discovery.
- **Targeted timeline**: focused on a host, account, file path, process, or incident window.

Most investigations use both.

## 6. Data Stored

Timeline data may include events from:

- MFT
- USN Change Journal
- `$LogFile`
- Windows Event Logs
- Prefetch
- Amcache
- ShimCache
- SRUM
- UserAssist
- ShellBags
- LNK files
- Jump Lists
- Run keys
- services
- scheduled tasks
- PowerShell logs
- WMI artifacts
- browser artifacts
- Defender logs
- EDR telemetry
- firewall, proxy, DNS, and VPN logs
- memory analysis output

The timeline itself is an analysis product. It should preserve source references so every event can be traced back to evidence.

## 7. Acquisition Methods

Timeline quality depends on collection quality. Collect source artifacts before building the timeline.

Minimum good practice:

- collect original artifacts where possible
- preserve timestamps and hashes
- normalize time zones to UTC
- record parser versions and commands
- keep raw parser output
- keep an analyst-reviewed timeline separate from raw extracted events
- document exclusions and missing sources

Common workflows:

| Workflow | Use Case |
| --- | --- |
| Manual targeted timeline | Small incident window, high precision. |
| Plaso/log2timeline | Broad multi-artifact extraction. |
| Timesketch | Collaborative review, tagging, saved views, notes. |
| SIEM/EDR export | Enterprise-scale event timeline. |
| Spreadsheet timeline | Report-ready curated event set. |

Do not let tool output become the final analysis without review.

## 8. Interpretation

Timeline interpretation requires caution with timestamps.

Example observations:

```text
03:21:52  Browser download starts
03:22:05  MFT file creation
03:22:07  Defender detection
03:23:02  Prefetch execution-related timestamp
03:23:04  EDR process creation
```

Reasonable inference:

- The file was likely downloaded, written to disk, detected, and then executed or attempted to execute shortly afterward.

Unsupported conclusion:

- "The account owner intentionally downloaded and executed malware."

That requires user context, phishing evidence, process lineage, and account/session analysis.

### Causation Warning

Temporal order does not prove causation. If A happened before B, A may have caused B, enabled B, coincided with B, or simply be unrelated. Correlation becomes stronger when artifacts independently support the same chain.

## 9. Strengths

Timeline analysis has several strengths:

- Shows sequence.
- Reveals gaps and contradictions.
- Connects artifacts into investigative narratives.
- Helps identify first known malicious activity.
- Supports scoping across hosts.
- Makes findings easier to explain.
- Helps separate evidence from inference.

A good timeline is often the backbone of a professional incident report.

## 10. Weaknesses

Limitations include:

- Timestamp sources have different meanings.
- Time zone errors can damage conclusions.
- Clock skew can affect multi-host timelines.
- Parser output can contain derived or misleading fields.
- High-volume timelines can hide important events.
- Missing artifacts can create false confidence.
- Anti-forensics can create conflicts.
- A timeline can imply causation if written carelessly.

Timeline analysis improves reasoning, but it does not eliminate uncertainty.

## 11. Common Mistakes

### Mistake 1: Mixing Local Time and UTC

Normalize to UTC and document conversions. Use local time only as a clearly labeled reporting aid.

### Mistake 2: Treating Every Timestamp Equally

MFT creation time, browser download start time, Event Log time, and Prefetch run time mean different things.

### Mistake 3: Building Only a Super Timeline

Broad timelines are useful for discovery, but findings usually require targeted timelines.

### Mistake 4: Ignoring Clock Skew

Multi-host incidents require time-source review. Domain controllers, servers, endpoints, and network devices may differ.

### Mistake 5: Writing Narrative Before Evidence

Let the timeline test the hypothesis. Do not force events into a preferred story.

## 12. Questions It Can Answer

Timeline analysis can often help answer:

- What happened first?
- What happened before and after a detection?
- Did file creation precede execution?
- Did logon precede remote execution?
- Did persistence appear before reboot or logon?
- Did cleanup follow execution?
- Which artifacts agree or conflict?
- Which evidence gaps require more collection?

## 13. Questions It Cannot Answer

Timeline analysis cannot answer by itself:

- Whether an event was malicious.
- Whether a user intended an action.
- Whether missing evidence means no activity.
- Whether one event caused another without supporting evidence.
- Whether timestamps are truthful without artifact-specific interpretation.
- Whether the timeline is complete.

## 14. Evidence Correlation

Correlation means using independent evidence to test a claim.

| Claim | Strong Correlation Pattern |
| --- | --- |
| File downloaded | Browser download + MFT/USN file creation + Zone.Identifier. |
| File executed | Prefetch + 4688/EDR + Amcache path/hash context. |
| RDP lateral movement | 4624 Type 10 + Terminal Services logs + source-host evidence. |
| Service persistence | 7045 + service Registry key + binary staged in MFT/USN + process telemetry. |
| PowerShell staging | 4104 command + MFT/USN created file + network logs. |
| Data exfiltration | Archive creation + process/network telemetry + proxy/firewall + destination/content evidence. |

### Correlation Map

```text
Observation
   |
   +--> Artifact-specific meaning
   |
   +--> Independent supporting artifact
   |
   +--> Alternative explanations tested
   |
   +--> Confidence statement
   |
   +--> Finding
```

## 15. Investigation Walkthrough

### Scenario

An alert reports suspicious outbound traffic from a workstation.

### Step 1: Build a Narrow Seed Timeline

Start with the alert time plus two hours before and after.

Observation:

- Network alert at 03:24 UTC.
- Suspicious process path in alert.

Inference:

- Use process path and alert time as pivots.

### Step 2: Add File System Events

Observation:

- MFT/USN show the executable was created at 03:22 UTC.

Inference:

- File staging preceded the network alert.

### Step 3: Add Browser and Origin Evidence

Observation:

- Browser download record shows the same filename from suspicious URL.

Inference:

- Browser evidence supports web-origin hypothesis.

### Step 4: Add Execution Evidence

Observation:

- Prefetch and EDR process creation show execution at 03:23 UTC.

Inference:

- Execution is supported independently.

### Step 5: Add Persistence and Cleanup

Observation:

- Run key created at 03:26 UTC.
- USN shows file deletion at 03:30 UTC.

Inference:

- Persistence followed execution; cleanup may have occurred afterward.

### Step 6: Write the Finding

Precise wording:

```text
The timeline shows a suspicious executable downloaded at 03:21:52 UTC, created on disk at 03:22:05 UTC, detected by Defender at 03:22:07 UTC, and executed at 03:23:04 UTC according to EDR telemetry. Network activity followed at 03:24 UTC. A Run key was created at 03:26 UTC pointing to the same executable path. These correlated artifacts support download, execution, network activity, and persistence configuration in sequence.
```

## 16. ASCII Timeline

```text
03:21:52  Browser: winupdate.exe download starts
03:22:05  MFT / USN: winupdate.exe created
03:22:07  Defender: threat detected
03:23:02  Prefetch: execution-related timestamp
03:23:04  EDR: winupdate.exe process starts
03:24:10  Network: outbound connection alert
03:26:04  Registry: Run key configured
03:30:20  USN: file deleted
```

## 17. Investigator's Mindset

Timeline building is disciplined storytelling. The story must be constrained by evidence.

Ask:

- What is directly observed?
- What does each timestamp actually mean?
- Are all times normalized?
- Are there clock skew concerns?
- What alternative explanations exist?
- Which artifacts independently support the same claim?
- Which events are missing?
- What confidence level is justified?

The goal is not a long timeline. The goal is a defensible timeline.

## 18. Key Takeaways

- Timeline analysis turns artifacts into incident reconstruction.
- Use UTC normalization and document time handling.
- Broad timelines help discovery; targeted timelines support findings.
- Timestamp meanings differ by artifact.
- Temporal order does not prove causation.
- Strong findings require independent artifact correlation.
- The final timeline should preserve source references and distinguish observation from inference.

## 19. Review Questions

1. Why is UTC normalization important?
2. What is the difference between broad and targeted timelines?
3. Why does temporal order not prove causation?
4. What artifacts would support a claim that a file was downloaded and executed?
5. How should an investigator handle conflicting timestamps?

## 20. References

- Plaso Documentation: https://plaso.readthedocs.io/
- Plaso GitHub, "Super timeline all the things": https://github.com/log2timeline/plaso
- Timesketch: https://timesketch.org/
- Timesketch GitHub: https://github.com/google/timesketch
- The Sleuth Kit Autopsy Documentation, "Plaso": https://sleuthkit.org/autopsy/docs/user-docs/4.22.0/plaso_page.html
- Forensics Wiki, "Plaso": https://forensics.wiki/plaso/
- Breitinger, Studiawan, Hargreaves, "SoK: Timeline based event reconstruction for digital forensics": https://arxiv.org/abs/2504.18131
