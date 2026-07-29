# Chapter 18: RDP, Logons, and Lateral Movement Artifacts

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why Windows records logon, logoff, credential validation, and Remote Desktop Protocol (RDP) events.
- Distinguish interactive, network, service, batch, and remote interactive logon types.
- Correlate Security events with Terminal Services logs during RDP investigations.
- Use logon artifacts to support lateral movement timelines.
- Avoid common mistakes involving source host, destination host, domain controller, and user intent.

## 2. Introduction

Logon evidence is central to Windows intrusion reconstruction. Attackers move through environments by authenticating to systems, creating sessions, running commands, copying files, and establishing persistence. Windows may record pieces of this activity in Security logs, Terminal Services logs, domain controller logs, process telemetry, and endpoint artifacts.

RDP is only one part of the logon story. Investigators must also recognize network logons, explicit credential use, service logons, scheduled task logons, and remote execution patterns.

The most important habit is to identify **where the event was recorded**. A Security 4624 on the destination host means a logon session was created there. A credential validation event on a domain controller means credentials were checked there. Those are related facts, not the same fact.

## 3. Why Windows Created This Artifact

Windows records authentication and session events for security auditing, accountability, access control, and troubleshooting. Microsoft documents Event ID 4624 as being generated when a logon session is created on the destination machine.

Remote Desktop Services also records operational events that help manage remote sessions. These logs support administration and troubleshooting, but they are valuable to investigators because they can show session creation, reconnection, disconnection, and authentication milestones.

## 4. Why Investigators Care

Logon artifacts help reconstruct attacker movement.

| Investigative Need | Logon Artifact Contribution |
| --- | --- |
| Initial access validation | Shows successful and failed authentication attempts. |
| Lateral movement | Reveals source and destination relationships. |
| RDP investigation | Terminal Services and Security logs support session reconstruction. |
| Credential misuse | Explicit credential and NTLM validation events provide leads. |
| Session timeline | Logon, reconnect, disconnect, and logoff events establish activity windows. |
| Persistence trigger context | Logon events explain Run key, Startup folder, and task execution. |
| Account scope | Shows whether activity used domain, local, service, or administrative accounts. |

Logon evidence often answers "how did the attacker get here?"

## 5. Internal Structure

Practical logon analysis uses several event families.

| Event / Log | Practical Meaning |
| --- | --- |
| Security 4624 | Successful logon session created on destination host. |
| Security 4625 | Failed logon attempt. |
| Security 4634 | Logon session terminated. |
| Security 4647 | User-initiated logoff. |
| Security 4648 | Explicit credentials were used. |
| Security 4776 | NTLM credential validation, often on a domain controller for domain accounts. |
| TerminalServices-RemoteConnectionManager 1149 | RDP authentication or session initialization context, OS-version dependent. |
| TerminalServices-LocalSessionManager 21 | Session logon succeeded. |
| TerminalServices-LocalSessionManager 24 | Session disconnected. |
| TerminalServices-LocalSessionManager 25 | Session reconnected. |

Important 4624 logon types include:

| Logon Type | Meaning | Common Investigative Context |
| --- | --- | --- |
| 2 | Interactive | Console or local interactive logon. |
| 3 | Network | SMB, remote service access, network authentication. |
| 4 | Batch | Scheduled task style activity. |
| 5 | Service | Service started by Service Control Manager. |
| 7 | Unlock | Workstation unlock. |
| 10 | RemoteInteractive | RDP or Terminal Services session. |
| 11 | CachedInteractive | Cached domain credentials. |

Logon type is a category, not a complete narrative.

## 6. Data Stored

Logon-related events may include:

- timestamp
- event ID
- computer where event was recorded
- target account
- account domain
- security identifier (SID)
- logon type
- logon ID
- source network address
- source port
- workstation name
- authentication package
- logon process
- elevated token indicator
- process name
- failure status and substatus
- session ID in Terminal Services logs

The `Logon ID` is useful for correlating events on the same host between reboots. It is not globally unique across systems.

## 7. Acquisition Methods

Acquire endpoint event logs:

```text
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
```

Also collect:

- domain controller Security logs
- Windows Event Forwarding (WEF) or Security Information and Event Management (SIEM) copies
- EDR authentication and process telemetry
- firewall/VPN/RD Gateway logs
- process creation logs
- MFT, USN, Prefetch, and persistence artifacts from destination hosts

Document:

- host role: workstation, server, domain controller, jump host, RD Gateway
- collection time in UTC
- logs collected
- log retention window
- time zone context
- whether logs are local, forwarded, or SIEM-normalized
- event source host and destination host

## 8. Interpretation

Interpret logon events by asking where the event was generated and what it actually records.

Example observation:

```text
Destination host: FILESRV01
Security Event ID: 4624
Logon Type: 10
Target Account: CORP\alex
Source Network Address: 10.10.4.25
Time: 2026-07-14 03:18:40 UTC
```

Reasonable inference:

- FILESRV01 recorded a remote interactive logon session for `CORP\alex` from `10.10.4.25`.
- This is consistent with RDP or Terminal Services access.

Unsupported conclusion:

- "Alex personally used RDP from that source."

The account may have been used by Alex, an administrator, malware, or an attacker with stolen credentials. User intent and physical presence require more evidence.

## 9. Strengths

Logon artifacts have several strengths:

- Provide account and session context.
- Help map source-to-destination movement.
- Support RDP session reconstruction.
- Can show failed attempts before success.
- Can reveal explicit credential use.
- Domain controller logs can confirm credential validation.
- Correlate well with process creation and persistence artifacts.

Logon evidence is often the frame around the rest of the incident timeline.

## 10. Weaknesses

Limitations include:

- Logs depend on audit policy and retention.
- Source IP may be missing, local, proxied, NATed, or a jump host.
- 4624 events can be numerous and noisy.
- Logon type does not prove user intent.
- Domain controller events and endpoint events show different parts of authentication.
- RDP event meanings vary by Windows version.
- Logon IDs are only locally useful between reboots.
- Attackers may clear logs or use legitimate admin pathways.

Never treat a single logon event as the whole lateral movement story.

## 11. Common Mistakes

### Mistake 1: Confusing Source and Destination

Security 4624 is recorded where the session was created. The source address is the connecting system, not the system where the event file resides.

### Mistake 2: Treating Logon Type 3 As RDP

Logon Type 3 is network logon, common for SMB and remote access. RDP commonly produces RemoteInteractive Type 10, though supporting Terminal Services logs are still needed.

### Mistake 3: Overtrusting Event 1149

Terminal Services 1149 is useful but has OS-version-dependent meaning. Correlate it with 4624 Type 10 and LocalSessionManager events.

### Mistake 4: Treating Account Use As Human Intent

An account name does not prove the account owner intentionally performed the action.

### Mistake 5: Ignoring Domain Controller Logs

For domain accounts, domain controller events such as 4776 or Kerberos events may provide credential validation context missing from the endpoint.

## 12. Questions It Can Answer

Logon artifacts can often help answer:

- Which account logged on to which host?
- What type of logon was recorded?
- What source address or workstation was recorded?
- Were there failed attempts before success?
- Was explicit credential use recorded?
- Did an RDP session log on, disconnect, reconnect, or log off?
- Does logon timing align with process execution, file staging, or persistence creation?

## 13. Questions It Cannot Answer

Logon artifacts cannot answer by themselves:

- Whether the account owner was physically present.
- Whether credentials were stolen.
- What commands were run after logon.
- Whether a source IP identifies the original attacker rather than a proxy or jump host.
- Whether missing events mean no access occurred.
- Whether activity was authorized.

## 14. Evidence Correlation

Logon evidence becomes powerful when paired with endpoint behavior.

| Correlating Artifact | Added Value |
| --- | --- |
| Security 4688 / EDR | Processes launched during the session. |
| Terminal Services logs | RDP session lifecycle. |
| Domain controller logs | Credential validation and authentication context. |
| Prefetch / Amcache | Execution-related evidence on destination host. |
| MFT / USN | File staging, tool transfer, deletion, and persistence files. |
| Services / Scheduled Tasks / WMI | Remote execution and persistence mechanisms. |
| Firewall / VPN / RD Gateway logs | Network path and external source context. |
| PowerShell logs | Command content after logon. |

### Correlation Map

```text
4624: account logs on to destination
        |
        +--> Terminal Services: RDP session lifecycle
        |
        +--> 4688 / EDR: commands and processes
        |
        +--> MFT / USN: files staged or deleted
        |
        +--> Services / tasks / WMI: persistence or remote execution
        |
        +--> DC / VPN / firewall: authentication and source path
```

## 15. Investigation Walkthrough

### Scenario

An internal file server shows suspicious service creation at 03:28 UTC.

### Step 1: Establish Remote Access

Observation:

- FILESRV01 Security log shows 4624 Type 10 for `CORP\alex` from `10.10.4.25` at 03:18 UTC.
- TerminalServices logs show a session logon around the same time.

Inference:

- Evidence supports RDP access to FILESRV01 using `CORP\alex`.

### Step 2: Check Failed Attempts

Observation:

- Several 4625 failures from `10.10.4.25` preceded the successful logon.

Inference:

- The pattern may support credential guessing, mistyped credentials, or attacker experimentation. More context is required.

### Step 3: Correlate Process Activity

Observation:

- EDR shows `cmd.exe` and `sc.exe` launched in the same user session.

Inference:

- Process telemetry connects the logon session to service creation activity.

### Step 4: Correlate File System Evidence

Observation:

- MFT and USN show `C:\Users\Public\winupdate.exe` created before service installation.

Inference:

- File staging likely occurred during or near the remote session.

### Step 5: Write the Finding

Precise wording:

```text
FILESRV01 recorded a RemoteInteractive logon for CORP\alex from 10.10.4.25 before suspicious service creation. Terminal Services logs support an RDP session, and EDR telemetry links the session to sc.exe execution. MFT and USN records show the referenced service binary was staged shortly before installation. These artifacts support lateral movement via RDP if source-host and account-owner context confirm the activity was unauthorized.
```

## 16. ASCII Timeline

```text
03:15:22  4625: failed logon from 10.10.4.25
03:18:40  4624 Type 10: CORP\alex RDP logon to FILESRV01
03:18:42  TerminalServices 21: session logon succeeded
03:22:11  MFT / USN: winupdate.exe created
03:27:58  4688 / EDR: sc.exe service creation command
03:28:12  7045: service installed
03:34:10  TerminalServices 24: session disconnected
```

## 17. Investigator's Mindset

Logon analysis is relationship analysis. Separate account, source, destination, authentication authority, and session behavior.

Ask:

- Which host recorded this event?
- Is this endpoint, domain controller, RD Gateway, VPN, or SIEM data?
- What logon type was recorded?
- What source address or workstation was recorded?
- What processes ran in the session?
- What files appeared after the logon?
- Was the activity expected for that account and host?
- What evidence shows the original source before a jump host?

The strongest lateral movement findings combine authentication, session, process, file, and network evidence.

## 18. Key Takeaways

- Security 4624 records logon session creation on the destination host.
- Logon type matters, but it is not the whole interpretation.
- RDP investigations should correlate Security logs with Terminal Services logs.
- Domain controller credential validation events show a different part of the authentication story.
- Account use does not prove account-owner intent.
- Logon evidence is strongest when correlated with process creation, file system changes, persistence artifacts, and network telemetry.

## 19. Review Questions

1. Why is event location important when interpreting 4624?
2. What is the difference between Logon Type 3 and Logon Type 10?
3. Why should Event 1149 be correlated with other events?
4. Which artifacts would you use to connect an RDP session to service creation?
5. Why does account use not prove human intent?

## 20. References

- Microsoft Learn, "4624(S): An account was successfully logged on": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- Microsoft Learn, "4634(S): An account was logged off": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634
- Microsoft Learn, "4648(S): A logon was attempted using explicit credentials": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648
- Microsoft Learn, "4776(S, F): The computer attempted to validate credentials": https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776
- Microsoft Learn, "Administrative tools and logon types reference": https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types
- Microsoft Learn, "Appendix L: Events to Monitor": https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
- Splunk Research, "Windows Event Log RemoteConnectionManager 1149": https://research.splunk.com/sources/08f9edb4-f95f-40be-b1dd-bc3a1cd95aaf/
- Cyber Triage, "Local Session Manager - Event 21": https://www.cybertriage.com/artifact/terminalservices_localsessionmanager_log/terminalservices_localsessionmanager_operational_21/
