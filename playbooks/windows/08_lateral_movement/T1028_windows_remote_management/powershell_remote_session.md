# PowerShell Remote Session

## Playbook Tags

**ID:** WINEXEC1905112233

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:** WINEXEC1904101010

## ATT&CK Tags

**Tactic:** Execution, Lateral Movement

**Technique:** PowerShell (T1086), Windows Remote Management (T1028)

## Applies To

## Technical Description

Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. In addition, it can be used to execute code remotely via Windows Remote Management (WinRM) services. Therefore, it is important to understand the basic artifacts left when PowerShell is used to execute code remotely via a remote powershell session.

## Permission Required

Administrator

## Hypothesis

Adversaries might be leveraging remote powershell sessions to execute code on remote systems throughout my environment

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_invoke_psremoting](https://github.com/Cyb3rWard0g/mordor/blob/acf9f6be6a386783a20139ceb2faf8146378d603/small_datasets/windows/execution/powershell_T1086/empire_invoke_psremoting.md) | A mordor dataset to simulate adversaries moving laterally via PSRemoting |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [4688](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4688.md) | A new process has been created | Microsoft-Windows-Security-Auditing | Detailed Tracking | Process Creation | Windows Event Logs |
| [1](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-1.md) | Process Creation | Microsoft-Windows-Sysmon | | | Process Monitoring |
| [3](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-3.md) | network Connect | Microsoft-Windows-Sysmon | | | Process use of network |
| [5156](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156) | The Windows Filtering Platform has permitted a connection | Microsoft-Windows-Security-Auditing | Object Access | Filtering Platform Connection | Windows Event Logs |
| [5158](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5158) | The Windows Filtering Platform has permitted a bind to a local port | Microsoft-Windows-Security-Auditing | Object Access | Filtering Platform Connection | Windows Event Logs |
| [400](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-400.md) | Engine Lifecycle | Windows PowerShell | | | PowerShell Logs |
| [4103](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-4103.md) | Module Logging | Microsoft-Windows-PowerShell |  |  | PowerShell Logs |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Medium | PowerShell | SELECT `@timestamp`, computer_name, channel FROM mordor_file WHERE (channel = "Microsoft-Windows-PowerShell/Operational" OR channel = "Windows PowerShell") AND (event_id = 400 OR event_id = 4103) AND message LIKE "%Host Application%wsmprovhost%" | Process wsmprovhost hosts the active remote session on the target. Therefore, it is important to monitor for any the initialization of the PowerShell host wsmprovhost |
| Low | Security | SELECT `@timestamp`, computer_name, Application, SourcePort, DestAddress, LayerName, LayerRTID FROM mordor_file WHERE channel = "Security" AND event_id = 5156 AND (DestPort = 5985 OR DestPort = 5986) AND LayerRTID = 44 | Monitor for any incoming network connection where the destination port is either 5985 or 5986. That will be hosted most likely by the System process. Layer ID:44 |
| Low | Security | SELECT `@timestamp`, computer_name, ParentProcessName, NewProcessName FROM mordor_file WHERE channel = "Security" AND event_id = 4688 AND (ParentProcessName LIKE "%wsmprovhost.exe" OR NewProcessName LIKE "%wsmprovhost.exe") | Process wsmprovhost hosts the active remote session on the target. Therefore, from a process creation perspective, it is to document any instances of wsmprovhost being spawned and spawning other processes |
| Low | Sysmon | SELECT `@timestamp`, computer_name, ParentImage, Image FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 1 AND (ParentImage LIKE "%wsmprovhost.exe" OR Image LIKE "%wsmprovhost.exe") | Process wsmprovhost hosts the active remote session on the target. Therefore, from a process creation perspective, it is to document any instances of wsmprovhost being spawned and spawning other processes |
| Low | Sysmon | SELECT `@timestamp`, computer_name, User, Initiated, Image, SourceIp, DestinationIp FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 3 AND (DestinationPort = 5985 OR DestinationPort = 5986) AND NOT User = "NT AUTHORITY\\\\NETWORK SERVICE" | Monitor for outbound network connection where the destination port is either 5985 or 5986 and the use is not NT AUTHORITY\NETWORK SERVICE |

## False Positives

## Detection Blind Spots

## Hunter Notes

* Explore the data produced in your lab environment with the analytics above and document what normal looks like from a PowerShell perspective. Then, take your findings and explore your production environment.
* If powershell activity locally or remotely via winrm happens all the time in  your environment, I suggest to categorize the data you collect by business unit or department to document profiles.
* Layer 44 translatest to layer filter FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 / FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6. This filtering layer allows for authorizing accept requests for incoming TCP connections, as well as authorizing incoming non-TCP traffic based on the first packet received. Looking for destination ports related to remote PowerShell Sessions and Layer 44 is very helpful.

## Hunt Output

| Category | Type | Name |
|--------|---------|---------|
| Signature | Sigma Rule | [powershell_remote_powershell_session.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/powershell_remote_powershell_session.yml) |
| Signature | Sigma Rule | [sysmon_remote_powershell_session_network.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_remote_powershell_session_network.yml) |
| Signature | Sigma Rule | [sysmon_remote_powershell_session_process.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_remote_powershell_session_process.yml) |
| Signature | Sigma Rule | [win_remote_powershell_session.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_remote_powershell_session.yml) |

## References

* https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-6#windows-powershell-remoting
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements?view=powershell-6
* https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-