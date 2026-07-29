# Windows Forensic Artifacts

## A Practical Guide to Evidence Correlation in Digital Forensics and Incident Response

**Prepared by Yasir Alharbi**  
Senior Cybersecurity Analyst | AI master's student | DFIR development track

This handbook is an investigation-first guide to Windows forensic artifacts for SOC analysts, DFIR analysts, incident responders, threat hunters, malware analysts, and FOR508/GCFA-oriented learners.

The central discipline is simple: separate observation, evidence, inference, assumption, and conclusion. Each chapter explains why an artifact exists, what it can and cannot prove, and how to correlate it with other evidence.

!!! info "Author and Portfolio"
    This handbook was prepared by **Yasir Alharbi** as an independent educational DFIR reference focused on Windows forensic artifact correlation and incident reconstruction.

    - Portfolio: [yasir-alharbi.github.io](https://yasir-alharbi.github.io/)
    - GitHub: [github.com/Yasir-Alharbi](https://github.com/Yasir-Alharbi)
    - LinkedIn: [linkedin.com/in/Yasir-T-Alharbi](https://www.linkedin.com/in/Yasir-T-Alharbi)

## Chapters

| # | Chapter |
| --- | --- |
| 1 | [Chapter 1: NTFS Master File Table (MFT)](chapters/01-chapter-1-ntfs-master-file-table-mft.md) |
| 2 | [Chapter 2: NTFS Update Sequence Number (USN) Change Journal](chapters/02-chapter-2-ntfs-update-sequence-number-usn-change-journal.md) |
| 3 | [Chapter 3: NTFS `$LogFile`](chapters/03-chapter-3-ntfs-logfile.md) |
| 4 | [Chapter 4: Windows Event Logs](chapters/04-chapter-4-windows-event-logs.md) |
| 5 | [Chapter 5: Windows Prefetch](chapters/05-chapter-5-windows-prefetch.md) |
| 6 | [Chapter 6: Amcache](chapters/06-chapter-6-amcache.md) |
| 7 | [Chapter 7: ShimCache / AppCompatCache](chapters/07-chapter-7-shimcache-appcompatcache.md) |
| 8 | [Chapter 8: System Resource Usage Monitor (SRUM)](chapters/08-chapter-8-system-resource-usage-monitor-srum.md) |
| 9 | [Chapter 9: UserAssist](chapters/09-chapter-9-userassist.md) |
| 10 | [Chapter 10: ShellBags](chapters/10-chapter-10-shellbags.md) |
| 11 | [Chapter 11: Windows Shortcut (LNK) Files](chapters/11-chapter-11-windows-shortcut-lnk-files.md) |
| 12 | [Chapter 12: Jump Lists](chapters/12-chapter-12-jump-lists.md) |
| 13 | [Chapter 13: Registry Run Keys and Startup Folder Persistence](chapters/13-chapter-13-registry-run-keys-and-startup-folder-persistence.md) |
| 14 | [Chapter 14: Windows Services and Drivers](chapters/14-chapter-14-windows-services-and-drivers.md) |
| 15 | [Chapter 15: Scheduled Tasks](chapters/15-chapter-15-scheduled-tasks.md) |
| 16 | [Chapter 16: PowerShell Logging](chapters/16-chapter-16-powershell-logging.md) |
| 17 | [Chapter 17: Windows Management Instrumentation (WMI) Persistence](chapters/17-chapter-17-windows-management-instrumentation-wmi-persistence.md) |
| 18 | [Chapter 18: RDP, Logons, and Lateral Movement Artifacts](chapters/18-chapter-18-rdp-logons-and-lateral-movement-artifacts.md) |
| 19 | [Chapter 19: Browser and Download Artifacts](chapters/19-chapter-19-browser-and-download-artifacts.md) |
| 20 | [Chapter 20: Windows Defender and Security Product Artifacts](chapters/20-chapter-20-windows-defender-and-security-product-artifacts.md) |
| 21 | [Chapter 21: Memory Forensics as Corroborating Evidence](chapters/21-chapter-21-memory-forensics-as-corroborating-evidence.md) |
| 22 | [Chapter 22: Timeline Building and Evidence Correlation](chapters/22-chapter-22-timeline-building-and-evidence-correlation.md) |
| 23 | [Chapter 23: Anti-Forensics, Timestomping, and Evidence Conflict](chapters/23-chapter-23-anti-forensics-timestomping-and-evidence-conflict.md) |
| 24 | [Chapter 24: End-to-End Investigation Walkthrough](chapters/24-chapter-24-end-to-end-investigation-walkthrough.md) |

## How to Use This Site

- Start with Chapters 1-4 if you are new to Windows artifact reasoning.
- Use Chapters 5-17 as artifact-specific references during investigation.
- Use Chapters 18-24 for lateral movement, source/origin analysis, memory corroboration, timeline building, anti-forensics, and complete incident reconstruction.

