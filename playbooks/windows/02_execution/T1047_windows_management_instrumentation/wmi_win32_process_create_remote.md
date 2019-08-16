# WMI Win32_Process Class and Create Method for Remote Execution

## Playbook Tags

**ID:** WINEXEC190810201010

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:**

## ATT&CK Tags

**Tactic:** Execution, Lateral Movement

**Technique:** Windows Management Instrumentation (T1047)

## Applies To

## Technical Description

WMI is the Microsoft implementation of the Web-Based Enterprise Management (WBEM) and Common Information Model (CIM). Both standards aim to provide an industry-agnostic means of collecting and transmitting information related to any managed component in an enterprise. An example of a managed component in WMI would be a running process, registry key, installed service, file information, etc. At a high level, Microsoft’s implementation of these standards can be summarized as follows: Managed Components Managed components are represented as WMI objects — class instances representing highly structured operating system data. Microsoft provides a wealth of WMI objects that communicate information related to the operating system. E.g. Win32_Process, Win32_Service, AntiVirusProduct, Win32_StartupCommand, etc.

One well known lateral movement technique is performed via the WMI object — class Win32_Process and its method Create. This is because the Create method allows a user to create a process either locally or remotely. One thing to notice is that when the Create method is used on a remote system, the method is run under a host process named “Wmiprvse.exe”.

The process WmiprvSE.exe is what spawns the process defined in the CommandLine parameter of the Create method. Therefore, the new process created remotely will have Wmiprvse.exe as a parent.
WmiprvSE.exe is a DCOM server and it is spawned underneath the DCOM service host svchost.exe with the following parameters C:\WINDOWS\system32\svchost.exe -k DcomLaunch -p.

From a logon session perspective, on the target, WmiprvSE.exe is spawned in a different logon session by the DCOM service host. However, whatever is executed by WmiprvSE.exe occurs on the new network type (3) logon session created by the user that authenticated from the network.

### Additional Reading

* [Logon Session](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/library/logon_session.md)

## Permission Required

User

## Hypothesis

Adversaries might be leveraging WMI Win32_Process class and method create to execute code remotely across my environment.

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_invoke_wmi](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/execution/windows_management_instrumentation_T1047/empire_invoke_wmi.md) | A mordor dataset to simulate the use of of WMI Win32_Process class and method Create to execute code remotely |
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_wmic_add_user_backdoor](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/execution/windows_management_instrumentation_T1047/empire_wmic_add_user_backdoor.md) | A mordor dataset to simulate the use of of WMI Win32_Process class and method Create to execute code remotely |
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_invoke_wmi_debugger](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/execution/windows_management_instrumentation_T1047/empire_invoke_wmi_debugger.md) | A mordor dataset to simulate the use of of WMI Win32_Process class and method Create to execute code remotely |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [4688](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4688.md) | A new process has been created | Microsoft-Windows-Security-Auditing | Detailed Tracking | Process Creation | Windows Event Logs |
| [4624](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4624.md) | An account was successfully logged on | Microsoft-Windows-Security-Auditing | Audit Logon/Logoff | Audit Logon | Windows Event Logs |
| [1](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-1.md) | Process Creation | Microsoft-Windows-Sysmon | | | Process Monitoring |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Medium | Security | SELECT `@timestamp`, computer_name, SubjectUserName, TargetUserName, NewProcessName, CommandLine FROM mordor_file WHERE channel = "Security" AND event_id = 4688 AND lower(ParentProcessName) LIKE "%wmiprvse.exe" AND NOT TargetLogonId = "0x3e7" | Look for wmiprvse.exe spawning processes that are part of non-system account sessions. |
| Medium | Sysmon | SELECT `@timestamp`, computer_name, User, Image, CommandLine FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 1 AND lower(ParentImage) LIKE "%wmiprvse.exe" AND NOT LogonId = "0x3e7" | Look for wmiprvse.exe spawning processes that are part of non-system account sessions. |
| Low | Security | SELECT o.`@timestamp`, o.computer_name, o.SubjectUserName, o.TargetUserName, o.NewProcessName, o.CommandLine, a.IpAddress FROM mordor_file o INNER JOIN (SELECT computer_name,TargetUserName,TargetLogonId,IpAddress FROM mordor_file WHERE channel = "Security" AND LogonType = 3 AND IpAddress is not null AND NOT TargetUserName LIKE "%$") a ON o.TargetLogonId = a.TargetLogonId WHERE o.channel = "Security" AND o.event_id = 4688 AND lower(o.ParentProcessName) LIKE "\%wmiprvse.exe" AND NOT o.TargetLogonId = "0x3e7" | Look for non-system accounts leveraging WMI over the netwotk to execute code |

## Detection Blind Spots

## Hunter Notes

* Stack the child processes of wmiprvse.exe in your environment. This is very helpful to reduce the number of false positive and understand your environment. You can categorize the data returned by business unit.
* Look for wmiprvse.exe spawning new processes that are part of a network type logon session.
* Enrich events with Network Logon events (4624 - Logon Type 3)

## Hunt Output

| Category | Type | Name |
|--------|---------|---------|
| Signature | Sigma Rule | [sysmon_wmiprvse_spawning_process.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_wmiprvse_spawning_process.yml) |
| Signature | Sigma Rule | [win_wmiprvse_spawning_process.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_wmiprvse_spawning_process.yml) |

## References

* https://posts.specterops.io/threat-hunting-with-jupyter-notebooks-part-4-sql-join-via-apache-sparksql-6630928c931e
* https://posts.specterops.io/real-time-sysmon-processing-via-ksql-and-helk-part-3-basic-use-case-8fbf383cb54f
* https://www.youtube.com/watch?v=iiaPeXEn5_E