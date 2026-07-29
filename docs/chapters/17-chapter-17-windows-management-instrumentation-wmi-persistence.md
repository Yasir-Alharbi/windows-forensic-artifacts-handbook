# Chapter 17: Windows Management Instrumentation (WMI) Persistence

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain why Windows Management Instrumentation (WMI) exists.
- Describe permanent WMI event subscriptions using filters, consumers, and bindings.
- Identify disk and telemetry sources relevant to WMI persistence.
- Interpret WMI evidence as trigger-action configuration requiring execution validation.
- Correlate WMI artifacts with PowerShell logs, process telemetry, MFT, USN, services, and event logs.

## 2. Introduction

Windows Management Instrumentation (WMI) is a management infrastructure for Windows. Administrators and applications use it to query system state, automate management, and respond to events.

Attackers abuse WMI for discovery, remote execution, lateral movement, and persistence. One especially important technique is the permanent WMI event subscription. A subscription can define a condition and an action so that when the condition occurs, WMI executes the configured consumer.

WMI persistence is powerful because it can be less obvious than Run keys, services, or scheduled tasks. It also may execute under high-privilege context depending on the consumer and configuration.

## 3. Why Windows Created This Artifact

Microsoft describes WMI as infrastructure for management data and operations on Windows-based operating systems. It gives scripts and applications a uniform interface for obtaining management data and performing operations locally or remotely.

Permanent event consumers allow WMI to respond to events. Microsoft documents that a permanent event consumer uses persistent objects and filters to capture WMI events; when an event matches the filter, WMI loads the consumer and notifies it.

This is legitimate automation infrastructure. The same eventing model can be abused for persistence.

## 4. Why Investigators Care

Investigators care because WMI subscriptions can hide attacker logic in a management database rather than in obvious Startup folders or service names.

| Investigative Need | WMI Contribution |
| --- | --- |
| Persistence discovery | Event subscriptions can execute commands when triggers occur. |
| Trigger analysis | Filters reveal what condition causes execution. |
| Action analysis | Consumers reveal command, script, or action content. |
| Binding validation | Bindings connect trigger to action. |
| Remote activity | WMI is often used for remote administration and lateral movement. |
| Anti-forensics awareness | Persistence may exist without a normal executable in Startup or Run keys. |
| ATT&CK mapping | Aligns with MITRE ATT&CK T1546.003. |

WMI persistence is a strong candidate when malware reappears but common autorun locations are clean.

## 5. Internal Structure

Permanent WMI event subscriptions are usually understood through three objects.

| Object | Role | Practical Question |
| --- | --- | --- |
| `__EventFilter` | Trigger condition | What event is being watched? |
| Event consumer | Action | What happens when the filter matches? |
| `__FilterToConsumerBinding` | Connector | Which trigger is connected to which action? |

Common consumer classes include:

- `CommandLineEventConsumer`
- `ActiveScriptEventConsumer`
- `LogFileEventConsumer`
- `NTEventLogEventConsumer`

`CommandLineEventConsumer` is especially important. Microsoft documents that it starts an arbitrary process on the local system when an event is delivered to it.

Persistent WMI repository data is commonly stored under:

```text
C:\Windows\System32\wbem\Repository\
```

Important files may include `OBJECTS.DATA`, index files, and mapping files depending on Windows version and repository state.

## 6. Data Stored

WMI persistence analysis may expose:

- namespace
- filter name
- WMI Query Language (WQL) query
- event consumer name
- consumer class
- command line or script text
- filter-to-consumer binding
- creator SID or security context where available
- repository timestamps
- event log records
- Sysmon WMI events if configured

The most important investigative question is whether a valid filter is bound to a consumer that launches suspicious code.

## 7. Acquisition Methods

Acquire WMI repository data:

```text
C:\Windows\System32\wbem\Repository\
```

Also collect:

- Microsoft-Windows-WMI-Activity event logs
- PowerShell logs
- Security and System event logs
- Sysmon logs if installed
- MFT and USN data for repository and referenced files
- scripts and binaries referenced by consumers
- EDR WMI telemetry

Live WMI enumeration can be useful but should not replace forensic collection. Malware or corruption can affect live views.

Document:

- host name
- collection time in UTC
- repository files collected
- namespaces queried
- enumeration tool and command line
- event logs collected
- whether source was live or offline

## 8. Interpretation

Interpret WMI subscriptions as trigger-action configuration.

Example observation:

```text
Filter: DailyUpdateFilter
Query: SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE ...
Consumer: CommandLineEventConsumer
CommandLineTemplate: powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\update.ps1
Binding: DailyUpdateFilter -> CommandLineEventConsumer
```

Reasonable inference:

- WMI contains a permanent event subscription configured to launch PowerShell with a script in `C:\Users\Public` when the filter condition is met.
- The consumer action and path are suspicious.

Unsupported conclusion:

- "The WMI subscription executed successfully."

Execution requires trigger evidence, process creation logs, PowerShell logs, EDR telemetry, or downstream file/network effects.

## 9. Strengths

WMI persistence evidence has several strengths:

- Shows hidden trigger-action automation.
- Can reveal persistence missed by common autorun checks.
- Consumer commands may expose attacker scripts or binaries.
- Bindings provide clear relationships between trigger and action.
- Sysmon can record filter, consumer, and binding creation when configured.
- Correlates strongly with PowerShell and process telemetry.

WMI evidence can explain recurring behavior that lacks ordinary Startup, service, or scheduled task artifacts.

## 10. Weaknesses

Limitations include:

- Repository parsing can be difficult.
- Live enumeration may miss deleted or corrupted historical evidence.
- Event logging may be limited unless WMI-Activity or Sysmon is available.
- Configuration does not prove trigger or successful execution.
- Legitimate management products use WMI heavily.
- Namespaces and consumers require specialized interpretation.
- Attackers may delete subscriptions after use.

WMI persistence is powerful but often requires deeper triage skill than Run keys or services.

## 11. Common Mistakes

### Mistake 1: Looking Only for Consumers

A consumer without a binding may not be active persistence. Confirm filter, consumer, and binding.

### Mistake 2: Ignoring the Trigger Query

The filter query explains when the action runs. It may trigger on time, logon, process creation, uptime, or another system condition.

### Mistake 3: Treating Subscription Presence As Execution

The subscription is configured automation. Confirm that it fired and launched the action.

### Mistake 4: Ignoring Legitimate WMI Use

Enterprise management and monitoring tools often use WMI. Suspiciousness depends on command, namespace, timing, creator, and behavior.

### Mistake 5: Ignoring Referenced Files

If the consumer launches a script or executable, investigate that file with MFT, USN, hashes, and execution artifacts.

## 12. Questions It Can Answer

WMI artifacts can often help answer:

- Is there a permanent WMI event subscription?
- What condition triggers it?
- What action does it execute?
- Is the filter bound to a consumer?
- Does the consumer launch a suspicious command, script, or binary?
- Does WMI evidence align with PowerShell, process, and file system activity?

## 13. Questions It Cannot Answer

WMI artifacts cannot answer by themselves:

- Whether the subscription fired.
- Whether the launched command succeeded.
- Whether the referenced script was malicious.
- Which remote host created the subscription without supporting telemetry.
- Whether a missing subscription means WMI was never abused.
- Whether all WMI activity was logged.

## 14. Evidence Correlation

WMI persistence should be correlated across repository, event, process, and file system evidence.

| Correlating Artifact | Added Value |
| --- | --- |
| WMI-Activity logs | WMI operation and error context. |
| Sysmon 19/20/21 | Event filter, consumer, and binding creation if configured. |
| PowerShell logs | Commands used to create or execute WMI actions. |
| Security 4688 / EDR | Process creation from WMI provider host or PowerShell. |
| MFT / USN | Referenced script or binary creation and deletion. |
| Scheduled Tasks / Services / Run keys | Alternative persistence comparison. |
| Network logs | Post-execution destination behavior. |

### Correlation Map

```text
WMI subscription: filter + consumer + binding
        |
        +--> PowerShell logs: creation command or launched script
        |
        +--> Sysmon / WMI-Activity: subscription creation or execution context
        |
        +--> MFT / USN: referenced file staged
        |
        +--> 4688 / EDR: command executed by WMI context
        |
        +--> Network logs: post-execution behavior
```

## 15. Investigation Walkthrough

### Scenario

A host repeatedly launches PowerShell shortly after boot, but Run keys, services, and scheduled tasks do not explain it.

### Step 1: Enumerate WMI Subscriptions

Observation:

- A permanent event subscription exists in `root\subscription`.
- The filter watches for system uptime or timer-related conditions.

Inference:

- WMI contains trigger logic that may explain recurring execution.

### Step 2: Inspect Consumer Action

Observation:

- The consumer is a `CommandLineEventConsumer`.
- It launches PowerShell with `C:\Users\Public\update.ps1`.

Inference:

- The action is suspicious and should be correlated with file and process evidence.

### Step 3: Validate Binding

Observation:

- A `__FilterToConsumerBinding` connects the filter to the consumer.

Inference:

- The trigger and action are connected as an active subscription.

### Step 4: Correlate Execution

Observation:

- EDR telemetry shows `WmiPrvSE.exe` launching `powershell.exe`.
- PowerShell logs show script block content from `update.ps1`.

Inference:

- Execution of the WMI-triggered action is supported.

### Step 5: Write the Finding

Precise wording:

```text
The host contains a permanent WMI event subscription consisting of an event filter, CommandLineEventConsumer, and binding. The consumer is configured to launch PowerShell with C:\Users\Public\update.ps1. Process telemetry showing WmiPrvSE.exe launching PowerShell and PowerShell logs from the referenced script support execution of the configured WMI persistence mechanism.
```

## 16. ASCII Timeline

```text
03:12:42  MFT / USN: update.ps1 created
03:14:18  PowerShell: WMI subscription creation command if logged
03:14:20  Sysmon 19/20/21: filter, consumer, binding if configured
08:00:05  WMI trigger condition met
08:00:06  EDR / 4688: WmiPrvSE.exe launches powershell.exe
08:00:07  4104: update.ps1 script block logged
```

## 17. Investigator's Mindset

WMI persistence is not one object. It is a relationship. Find the trigger, the action, and the binding.

Ask:

- Which namespace contains the subscription?
- What does the filter query watch for?
- What consumer class is used?
- What command, script, or executable is configured?
- Is there a binding connecting filter and consumer?
- What created the subscription?
- Did WMI actually launch the action?
- What happened after launch?

Think in trigger-action-correlation terms.

## 18. Key Takeaways

- WMI is legitimate Windows management infrastructure.
- Permanent WMI event subscriptions can be abused for persistence.
- The core model is filter, consumer, and binding.
- `CommandLineEventConsumer` can launch a process when an event is delivered.
- Repository evidence should be correlated with WMI-Activity, Sysmon, PowerShell, process, and file system evidence.
- Subscription presence proves configuration, not successful execution.
- Strong findings validate trigger, action, binding, and execution behavior.

## 19. Review Questions

1. What are the three core components of a permanent WMI event subscription?
2. Why is a binding important?
3. What does `CommandLineEventConsumer` do?
4. Why does subscription presence not prove execution?
5. Which artifacts would you use to confirm WMI-triggered PowerShell execution?

## 20. References

- Microsoft Learn, "Windows Management Instrumentation": https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page
- Microsoft Learn, "WMI Architecture": https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-architecture
- Microsoft Learn, "Receiving a WMI Event": https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event
- Microsoft Learn, "CommandLineEventConsumer class": https://learn.microsoft.com/en-us/windows/win32/wmisdk/commandlineeventconsumer
- MITRE ATT&CK, "Event Triggered Execution: Windows Management Instrumentation Event Subscription": https://attack.mitre.org/techniques/T1546/003/
- SANS, "Finding Evil WMI Event Consumers with Disk Forensics": https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics
- Elastic, "Persistence via WMI Event Subscription": https://www.elastic.co/guide/en/security/current/persistence-via-wmi-event-subscription.html
