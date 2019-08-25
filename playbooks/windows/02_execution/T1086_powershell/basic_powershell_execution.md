# Basic PowerShell Execution

## Playbook Tags

**ID:** WINEXEC1905101511

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:**

## ATT&CK Tags

**Tactic:** Execution

**Technique:** PowerShell (T1086)

## Applies To

## Technical Description

Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Therefore, it is important to understand the basic artifacts left when PowerShell is used in your environment.

## Permission Required

User

## Hypothesis

Adversaries might be leveraging PowerShell to execute code within my environment

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_launcher_vbs](https://github.com/Cyb3rWard0g/mordor/blob/acf9f6be6a386783a20139ceb2faf8146378d603/small_datasets/windows/execution/scripting_T1064/empire_launcher_vbs.md) | A mordor dataset to simulate execution of PowerShell not interactively |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [4688](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4688.md) | A new process has been created | Microsoft-Windows-Security-Auditing | Detailed Tracking | Process Creation | Windows Event Logs |
| [1](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-1.md) | Process Creation | Microsoft-Windows-Sysmon | | | Process Monitoring |
| [7](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-7.md) | Image Loaded | Microsoft-Windows-Sysmon | | | Loaded DLLs |
| [17](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-7.md) | Pipe Created | Microsoft-Windows-Sysmon | | | Named Pipes |
| [400](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-400.md) | Engine Lifecycle | Windows PowerShell | | | PowerShell Logs |
| 53504 | PowerShell Named Pipe IPC | Microsoft-Windows-PowerShell | | | PowerShell Logs |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Medium | PowerShell | SELECT `@timestamp`, computer_name, channel FROM mordor_file WHERE (channel = "Microsoft-Windows-PowerShell/Operational" OR channel = "Windows PowerShell") AND (event_id = 400 OR event_id = 4103) | Within the classic PowerShell log, event ID 400 indicates when a new PowerShell host process has started. You can filter on powershell.exe as a host application if you want to or leave it without a filter to captuer every single PowerShell host |
| High | Security | SELECT `@timestamp`, computer_name, NewProcessName, ParentProcessName FROM mordor_file WHERE channel = "Security" AND event_id = 4688 AND NewProcessName LIKE "%powershell.exe" AND NOT ParentProcessName LIKE "%explorer.exe" | Looking for non-interactive powershell session might be a sign of PowerShell being executed by another application in the background |
| High | Sysmon | SELECT `@timestamp`, computer_name, Image, ParentImage FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 1 AND Image LIKE "%powershell.exe" AND NOT ParentImage LIKE "%explorer.exe" | Looking for non-interactive powershell session might be a sign of PowerShell being executed by another application in the background |
| Medium | Sysmon | SELECT `@timestamp`, computer_name, Image, ImageLoaded FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 7 AND (lower(Description) = "system.management.automation" OR lower(ImageLoaded) LIKE "%system.management.automation%") | Monitor for processes loading PowerShell DLL \*system.management.automation\* |
| Low | Sysmon |  SELECT `@timestamp`, computer_name, Image, PipeName FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 17 AND lower(PipeName) LIKE "\\\\pshost%" | Monitoring for PSHost* pipes is another interesting way to find PowerShell execution |
| High | PowerShell | SELECT `@timestamp`, computer_name, param1, param2 FROM mordor_file WHERE channel = "Microsoft-Windows-PowerShell/Operational" AND event_id = 53504 | The “PowerShell Named Pipe IPC” event will indicate the name of the PowerShell AppDomain that started. Sign of PowerShell execution |

## False Positives

## Detection Blind Spots

## Hunter Notes

* Explore the data produced in your environment with the analytics above and document what normal looks like from a PowerShell perspective.
* If execution of PowerShell happens all the time in your environment, I suggest to categorize the data you collect by business unit to build profiles and be able to filter out potential noise.
* You can also stack the values of the command line arguments being used. You can hash the command line arguments too and stack the values.

## Hunt Output

| Category | Type |  Name |
|--------|---------|---------|
| Signature | Sigma Rule | [sysmon_powershell_execution_moduleload.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_powershell_execution_moduleload.yml) |
| Signature | Sigma Rule | [sysmon_powershell_execution_pipe.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_powershell_execution_pipe.yml) |
| Signature | Sigma Rule | [sysmon_non_interactive_powershell_execution.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_non_interactive_powershell_execution.yml) |
| Signature | Sigma Rule | [win_non_interactive_powershell.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_non_interactive_powershell.yml) |

## References

* https://github.com/darkoperator/Presentations/blob/master/PSConfEU%202019%20Tracking%20PowerShell%20Usage.pdf
* https://posts.specterops.io/abusing-powershell-desired-state-configuration-for-lateral-movement-ca42ddbe6f06