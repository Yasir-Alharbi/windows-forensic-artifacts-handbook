# Chapter 14: Windows Services and Drivers

## 1. Learning Objectives

By the end of this chapter, the reader should be able to:

- Explain how Windows stores service and driver configuration.
- Identify key Registry values such as `ImagePath`, `Start`, `Type`, and `ObjectName`.
- Use event logs to detect service installation and startup failures.
- Interpret service evidence as configuration, installation, and execution context.
- Correlate services with MFT, USN, Prefetch, Amcache, Event Logs, and EDR telemetry.

## 2. Introduction

Windows services are background programs managed by the Service Control Manager. Drivers are lower-level components used by the operating system and hardware. Both are configured in the Registry under:

```text
HKLM\SYSTEM\CurrentControlSet\Services
```

Attackers frequently abuse services for persistence, privilege escalation, lateral movement, and execution under powerful accounts such as LocalSystem. Remote service creation is also common during lateral movement.

Service artifacts are high-value because they can show what was installed, what binary was configured, how it starts, and under which account context it runs. But service configuration alone does not prove the binary executed successfully.

## 3. Why Windows Created This Artifact

Windows needs a structured way to manage long-running background components. Services support system functions, security products, update agents, business software, database engines, remote access tools, and many administrative components.

The Registry service tree stores local service and driver configuration. Microsoft documents values such as `ImagePath`, which specifies the path to the service binary, along with other service configuration values.

The forensic value comes from the fact that these settings are persistent and often connected to high-privilege execution.

## 4. Why Investigators Care

Investigators care because malicious or suspicious services can explain persistence and privileged execution.

| Investigative Need | Service/Driver Contribution |
| --- | --- |
| Persistence discovery | Auto-start services can run at boot or service start. |
| Privilege context | Services may run as LocalSystem or another privileged account. |
| Lateral movement | Remote service creation is a common execution technique. |
| Malware staging | `ImagePath` may point to suspicious binaries or scripts. |
| Driver abuse | Kernel drivers may indicate rootkit, EDR tampering, or vulnerable driver abuse. |
| Timeline support | Registry last write and event logs help sequence installation. |
| Attribution support | Event logs and EDR may identify the creating process and account. |

Service evidence can turn a suspicious executable into a persistence and privilege story.

## 5. Internal Structure

Each service or driver usually has a subkey beneath:

```text
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
```

Common values include:

| Value | Practical Meaning |
| --- | --- |
| `ImagePath` | Path or command used for the service binary or driver. |
| `DisplayName` | Friendly service name. |
| `Description` | Human-readable description. |
| `Start` | Startup type, such as boot, system, automatic, manual, or disabled. |
| `Type` | Service or driver type. |
| `ObjectName` | Account context for Win32 services. |
| `ServiceDll` | DLL path for services hosted by `svchost.exe`, commonly under `Parameters`. |
| `FailureActions` | Recovery behavior if service fails. |

Hosted services require special care. If `ImagePath` points to `svchost.exe`, inspect the service's parameters and service DLL configuration.

## 6. Data Stored

Service analysis may expose:

- service name
- display name
- description
- binary path or driver path
- hosted service DLL path
- start type
- service type
- account context
- dependencies
- failure actions
- Registry key last write time
- event log installation time
- service start, stop, or failure events
- file system metadata for referenced binaries

The most important field for triage is often `ImagePath`, but it should not be read in isolation.

## 7. Acquisition Methods

Acquire:

```text
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SYSTEM.LOG1
C:\Windows\System32\config\SYSTEM.LOG2
```

Also collect:

- System event log
- Security event log
- Sysmon log if installed
- referenced service binaries
- referenced service DLLs
- MFT and USN data for referenced paths
- EDR service creation or registry modification telemetry

Useful live-response commands include service enumeration through PowerShell, `sc.exe`, Sysinternals Autoruns, or EDR inventory. For forensic analysis, preserve the underlying hives and event logs.

Document:

- host name
- collection time in UTC
- SYSTEM hive and logs collected
- event logs collected
- referenced binaries collected
- tool and parser versions
- whether source was live or offline

## 8. Interpretation

Service evidence should be interpreted in layers: configuration, installation, execution, and behavior.

Example observation:

```text
Service name: WindowsUpdateSvc
ImagePath: C:\Users\Public\winupdate.exe
Start: Auto
ObjectName: LocalSystem
System Event ID 7045: service installed at 2026-07-14 03:28:12 UTC
```

Reasonable inference:

- Windows recorded installation of a service named `WindowsUpdateSvc`.
- The service is configured to run a suspicious binary from `C:\Users\Public`.
- The service is configured for automatic start and LocalSystem context.

Unsupported conclusion:

- "The service successfully ran and connected to command and control."

Execution and network behavior require service start events, process telemetry, Prefetch, EDR, firewall logs, or memory evidence.

## 9. Strengths

Service and driver artifacts have several strengths:

- Strong persistence and privilege context.
- Registry configuration is explicit and inspectable.
- Event ID 7045 can show service installation.
- `ImagePath` can reveal suspicious commands or paths.
- Services often run with elevated privileges.
- Drivers can reveal deeper system modification.
- Correlates well with lateral movement and remote execution investigations.

Service creation is often one of the clearest signs of attacker persistence or remote execution.

## 10. Weaknesses

Limitations include:

- Service keys prove configuration, not successful execution.
- Legitimate services are numerous and noisy.
- Event logs may roll over or be cleared.
- Hosted services require DLL-level inspection.
- Service names and descriptions can be deceptive.
- Registry last write time is key-level, not value-level.
- Deleted services may require transaction logs, backups, EDR, or event logs.
- Driver analysis can require specialized malware and kernel knowledge.

Suspicious service analysis requires context, not just a strange name.

## 11. Common Mistakes

### Mistake 1: Trusting DisplayName and Description

Attackers can name services after legitimate Windows components. Inspect path, signer, hash, account, and timing.

### Mistake 2: Ignoring Hosted Service DLLs

If a service uses `svchost.exe`, the malicious component may be in `ServiceDll`, not `ImagePath`.

### Mistake 3: Treating 7045 As Full Attribution

Event 7045 shows service installation information, but attribution may require Security logs, process creation logs, and EDR telemetry.

### Mistake 4: Ignoring Service Account Context

`ObjectName` matters. LocalSystem service execution has different impact than a low-privilege user context.

### Mistake 5: Ignoring File System Evidence

Always investigate the referenced binary or DLL. The Registry value is only a pointer.

## 12. Questions It Can Answer

Service and driver artifacts can often help answer:

- Was a service or driver configured on the host?
- What binary, DLL, or driver path was configured?
- What startup type was configured?
- What account context was configured?
- Was a new service installation event recorded?
- Does the service path point to a suspicious location?
- Does service creation align with logon, file staging, or lateral movement evidence?

## 13. Questions It Cannot Answer

These artifacts cannot answer by themselves:

- Whether the service successfully started.
- Whether the binary was malicious.
- Which process created the service without supporting logs.
- Whether the service connected to the network.
- Whether the service was installed by an attacker or administrator.
- Whether deleted service evidence never existed.

## 14. Evidence Correlation

Service evidence should be correlated across Registry, event logs, process telemetry, and file system artifacts.

| Correlating Artifact | Added Value |
| --- | --- |
| System Event 7045 | New service installation record. |
| Security 4697 | Service installation auditing where available. |
| Security 4688 / Sysmon 1 | Process creation, parent process, command line. |
| MFT / USN | Referenced binary creation, modification, deletion. |
| Amcache / ShimCache | Program metadata and path leads. |
| Prefetch | Execution-related evidence for service binary where applicable. |
| EDR telemetry | Registry write, service creation, process lineage, account, network. |
| Network logs | Destination and connection behavior. |

### Correlation Map

```text
Service key: suspicious ImagePath
        |
        +--> Event 7045 / 4697: installation timing and service details
        |
        +--> MFT / USN: binary staged before installation
        |
        +--> 4688 / EDR: sc.exe, PowerShell, or remote creation process
        |
        +--> Service start / process telemetry: did it run?
        |
        +--> Network logs: what did it do?
```

## 15. Investigation Walkthrough

### Scenario

A domain server shows suspicious outbound traffic after an administrator account logged on remotely.

### Step 1: Inspect Service Installation Events

Observation:

- System Event 7045 records installation of `WindowsUpdateSvc`.
- The service binary path is `C:\Users\Public\winupdate.exe`.

Inference:

- Windows recorded installation of a new service pointing to a suspicious user-writable path.

### Step 2: Inspect Registry Configuration

Observation:

- SYSTEM hive shows the service configured with `Start=2` and `ObjectName=LocalSystem`.

Inference:

- The service is configured for automatic start and privileged execution context.

### Step 3: Correlate File Staging

Observation:

- MFT and USN records show `winupdate.exe` was created minutes before the service installation.

Inference:

- File staging likely preceded service persistence configuration.

### Step 4: Attribute Creation

Observation:

- EDR telemetry shows `sc.exe create` executed from a remote administrative session.

Inference:

- Remote service creation is supported by process and session evidence.

### Step 5: Write the Finding

Precise wording:

```text
System Event 7045 and the SYSTEM hive show a newly installed service named WindowsUpdateSvc configured to run C:\Users\Public\winupdate.exe as LocalSystem with automatic startup. MFT and USN records show the binary was staged shortly before service creation. Process telemetry indicating sc.exe or PowerShell service creation from a remote logon session is required to attribute creation to an account and source host.
```

## 16. ASCII Timeline

```text
03:18:40  4624: remote administrative logon
03:22:11  MFT / USN: winupdate.exe created in C:\Users\Public
03:28:12  7045: WindowsUpdateSvc installed
03:28:14  Registry: service key updated
03:28:20  4688 / EDR: service binary starts if available
03:29:02  Network telemetry: outbound connection
```

## 17. Investigator's Mindset

Service analysis is about control and context. Ask what was configured, who configured it, whether it ran, and what privileges it had.

Ask:

- What is the service name and display name?
- What does `ImagePath` or `ServiceDll` actually execute?
- Is the path expected for legitimate software?
- What account context is configured?
- Was Event 7045 or 4697 recorded?
- What process created or modified the service?
- Did the service start successfully?
- What behavior followed execution?

Separate installation, startup, and behavior in your findings.

## 18. Key Takeaways

- Service and driver configuration is stored under `HKLM\SYSTEM\CurrentControlSet\Services`.
- `ImagePath`, `Start`, `Type`, `ObjectName`, and `ServiceDll` are key investigative fields.
- Event 7045 can record new service installation.
- Service configuration proves configuration, not successful execution.
- Hosted services require DLL-level inspection.
- Services can provide persistence and privileged execution.
- Strong findings correlate Registry data, event logs, process telemetry, file system artifacts, and network evidence.

## 19. Review Questions

1. Where is Windows service configuration stored?
2. Why is `ImagePath` important?
3. Why must hosted services be inspected differently?
4. What does Event 7045 contribute?
5. Which artifacts would you use to prove a suspicious service actually ran?

## 20. References

- Microsoft Learn, "HKLM\SYSTEM\CurrentControlSet\Services Registry Tree": https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree
- Microsoft Learn, "Create a user-defined service": https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/create-user-defined-service
- Microsoft Learn, "Autoruns for Windows": https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- Splunk Research, "Windows Event Log System 7045": https://research.splunk.com/sources/614dedc8-8a14-4393-ba9b-6f093cbcd293/
- MITRE ATT&CK, "System Services: Service Execution": https://attack.mitre.org/techniques/T1569/002/
- MITRE ATT&CK, "Create or Modify System Process: Windows Service": https://attack.mitre.org/techniques/T1543/003/
