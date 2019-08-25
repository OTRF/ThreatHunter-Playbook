# Alternate PowerShell Hosts

## Playbook Tags

**ID:** WINEXEC190610201010

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:** WINEXEC1904101010

## ATT&CK Tags

**Tactic:** Execution

**Technique:** PowerShell (T1086)

## Applies To

## Technical Description

Adversaries can abuse alternate signed PowerShell Hosts to evade application whitelisting solutions that block powershell.exe and naive logging based upon traditional PowerShell hosts.

Characteristics of a PowerShell host (Matt Graeber @mattifestation):

* These binaries are almost always C#/.NET .exes/.dlls
* These binaries have System.Management.Automation.dll as a referenced assembly
* These may not always be “built in” binaries

## Permission Required

User

## Hypothesis

Adversaries might be leveraging alternate PowerShell Hosts to execute PowerShell evading traditional PowerShell detections that look for powershell.exe in my environment.

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_invoke_psremoting](https://github.com/Cyb3rWard0g/mordor/blob/acf9f6be6a386783a20139ceb2faf8146378d603/small_datasets/windows/execution/powershell_T1086/empire_invoke_psremoting.md) | A mordor dataset to simulate adversaries moving laterally via PSRemoting |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [400](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-400.md) | Engine Lifecycle | Windows PowerShell | - | - | PowerShell Logs |
| [4103](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-4103.md) | Module Logging | Microsoft-Windows-PowerShell | - | - | PowerShell Logs |
| [7](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-7.md) | Image Loaded | Microsoft-Windows-Sysmon | - | - | Loaded DLLs |
| [17](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-7.md) | Pipe Created | Microsoft-Windows-Sysmon | - | - | Named Pipes |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Medium | PowerShell | SELECT `@timestamp`, computer_name, channel FROM mordor_file WHERE (channel = "Microsoft-Windows-PowerShell/Operational" OR channel = "Windows PowerShell") AND (event_id = 400 OR event_id = 4103) AND NOT message LIKE "%Host Application%powershell%" | Within the classic PowerShell log, event ID 400 indicates when a new PowerShell host process has started. Excluding PowerShell.exe is a good way to find alternate PowerShell hosts |
| Medium | Sysmon |  SELECT `@timestamp`, computer_name, Image, Description FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 7 AND (lower(Description) = "system.management.automation"OR lower(ImageLoaded) LIKE "%system.management.automation%") AND NOT Image LIKE "%powershell.exe"  | Looking for processes loading a specific PowerShell DLL is a very effective way to document the use of PowerShell in your environment |
| Low | Sysmon |  SELECT `@timestamp`, computer_name, Image, PipeName FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 17 AND lower(PipeName) LIKE "\\\\\pshost%" AND NOT Image LIKE "%powershell.exe" | Monitoring for PSHost* pipes is another interesting way to find other alternate PowerShell hosts in your environment. |

## False Positives

## Detection Blind Spots

## Hunter Notes

* Explore the data produced in your lab environment with the analytics above and document what normal looks like from alternate powershell hosts. Then, take your findings and explore your production environment.
* You can also run the script below named PowerShellHostFinder.ps1 by Matt Graber and audit PS host binaries in your environment.

## Hunt Output

| Category | Type | Name |
|--------|---------|---------|
| Signature | Sigma Rule | [powershell_alternate_powershell_hosts.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/powershell_alternate_powershell_hosts.yml) |
| Signature | Sigma Rule | [sysmon_alternate_powershell_hosts_moduleload.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_alternate_powershell_hosts_moduleload.yml) |
| Signature | Sigma Rule | [sysmon_alternate_powershell_hosts_pipe.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_alternate_powershell_hosts_pipe.yml) |

## References

* https://twitter.com/mattifestation/status/971840487882506240
* https://gist.githubusercontent.com/mattifestation/fcae777470f1bdeb9e4b32f93c245fd3/raw/abbe79c660829ab9aad58581baf681655f6ba305/PowerShellHostFinder.ps1