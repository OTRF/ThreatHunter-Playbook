# PowerShell Remote Execution via WinRM

## Technique ID(s)

T1086,T1028

## Tactic Name(s)

Execution,Lateral Movement

## Description

Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. In addition, it can be used to execute code remotely via Windows Remote Management (WinRM) services. Therefore, it is important to understand the basic artifacts left when PowerShell is used to execute code remotely via WinRM.

## Hypothesis

Adversaries might be leveraging WinRM via PowerShell to execute code on remote systems throughout my environment

## Attack Simulation

### Attack Simulation Requirements

Endpoints Event logging: Enable All (It is difficult to know what you need to enable if you have never tested the specific technique before)

Execution of PowerShell remotely requires:

* Source & destination endpoints to set their network connection profile type to domain or private
* Source & destination endpoints to open the PowerShell console as an Administrator
* Source & destination endpoints to run `Enable-PSRemoting`
* Source endpoint to run `winrm s winrm/config/client '@{TrustedHosts="REMOTE-ENDPOINT-NAME"}'`

### Attack Simulation Details

| type  | Steps/commands | Description | Author | Link/Reference |
|---------|---------|---------|---------|---------|
| command | `invoke-command -scriptblock {get-process} -Credential username -ComputerName REMOTE-ENDPOINT-NAME` | Remote execution of powershell via PowerShell Console | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) | |

## Recommended Data Sources

| Behavior Identified | Data Source | Log Name | Category | Sub-category | Event Id |
|---------|---------|---------|---------|---------|---------|
| Process Creation | Microsoft-Windows-Security-Auditing | Security | Detailed Tracking | Process Creation | 4688 |
| Process Creation | Microsoft-Windows-Sysmon | Microsoft-windows-sysmon/operational | Process Created | | 1 |
| Module Loaded | Microsoft-Windows-Sysmon | Microsoft-windows-sysmon/operational | Image Loaded | | 7 |
| Win Pipe Creation | Windows Sysmon | Microsoft-windows-sysmon/operational | Pipe Created | | 17 |
| PowerShell Execution | PowerShell | Windows PowerShell | Engine Lifecycle |  | | 400 |
| PowerShell Execution | Microsoft-Windows-PowerShell  | Microsoft-windows-PowerShell/Operational | Module Logging | | 4103 |
| Process Network Connection | Microsoft-Windows-Security-Auditing | Security | Object Access | Filtering Platform Connection | 5156 |
| Process Bind to Local Port | Microsoft-Windows-Security-Auditing | Security | Object Access | Filtering Platform Connection | 5158 |

### Needed Event Logging Configurations

| Requirement | Details | Reference |
|---------|---------|---------|
| Enable PowerShell Module Logging | Computer configuration > Administrative Templates: Policy Definitions > Windows Components > Windows PowerShell > Turn on Module Logging | [Cyb3rward0g](https://cyberwardog.blogspot.com/2017/06/enabling-enhanced-ps-logging-shipping.html) |
| Enable Windows Filtering Platform Logging  | auditpol.exe /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable | Cyb3rWard0g |
| PowerShell Logs Parser | PowerShell logs need to be parsed properly to allow hunters access the right data fields needed to create analytics. PowerShell Logs are not parsed by deafult by several SIEM solutions | [@neu5ron](https://gist.github.com/neu5ron/450289373db61d5c8d7378e79455ef07#file-511-windows-event-powershell-operational-conf) |

## Data Quality Assessment

| Data Dimension | Score | Description |
|---------|---------|---------|
| Completeness | | |
| Consistencty | | |
| Timeliness | | |

## Data Analytics

| Analytic Goal | Location | Analytic Type | Analytic Logic | Analytic Data Object |
|--------|---------|---------|---------|---------|
| Degect execution of PowerShell via modules loaded | Source, Target | Situational Awareness | (modules_loaded OR event_id:7) WHERE file_description:system.management.automation OR module_loaded:\*system.management.automation\* | [module](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/module.md) |
| Detect execution of PowerShell via pipe creation | Source, Target | Situational Awareness | (pipe_create OR event_id:17) WHERE pipe_name:\*PSHost\* | [pipe](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/pipe.md) |
| Detect execution of PowerShell via process creation | source | Situational Awareness | (process_create OR event_id:1 OR event_id:4688) WHERE process_name:powershell.exe OR process_parent_name:powershell.exe | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/process.md) |
| Detect execution of PowerShell via process creation | Target | Situational Awareness | (process_create OR event_id:1) WHERE process_name:wsmprovhost.exe | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/process.md) |
| Detect execution of PowerShell via PowerShell Logs | Source | Situational Awareness | (powershell_logs OR event_id:400) WHERE powershell_host_name:ConsoleHost OR powershell_host_application:\*powershell.exe\* | [powershell engine](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/powershell_engine.md) |
| Detect execution of PowerShell via PowerShell Logs | Target | Situational Awareness | (powershell_logs OR event_id:400) WHERE powershell_host_name:ServerRemoteHost OR powershell_host_application:\*wsmprovhost.exe\* | [powershell engine](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/powershell_engine.md) |
| Detect execution of PowerShell via PowerShell Logs | Target | Situational Awareness | (powershell_logs OR event_id:4103) WHERE powershell_host_name:ServerRemoteHost OR powershell_host_application:\*wsmprovhost.exe\* | [powershell module log](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/powershell_module_log.md) |
| Detect execution of PowerShell via Windows Filtering Platform logs | Local | Situational Awareness | (process_bind_to_local_port OR event_id:5158) WHERE process_name:powershell.exe | [Process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/process.md),[IP](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/ip.md) |
| Detect execution of PowerShell via Windows Filtering Platform logs | Local | Situational Awareness | (process_network_connections OR event_id:5156) WHERE process_name:powershell.exe OR dst_port:(5985 OR 5986) AND (network_layer_id:48 OR network_direction:outbound) | [Process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/process.md),[IP](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/ip.md) |
| Detect execution of PowerShell via Windows Filtering Platform logs | Remote | Situational Awareness | (process_network_connections OR event_id:5156) WHERE process_name:powershell.exe OR dst_port:(5985 OR 5986) AND (network_layer_id:44 OR network_direction:inbound) | [Process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/process.md),[IP](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/ip.md) |

## Hunter Notes

* Explore the data produced in your lab environment with the analytics above and document what normal looks like from a PowerShell perspective. Then, take your findings and explore your production environment.
* If powershell activity locally or remotely via winrm happens all the time in  your environment, I suggest to categorize the data you collect by business unit or department to document profiles.

## Hunting Techniques Recommended

- [x] Query Searching
- [x] Data Grouping
- [ ] Data Aggregating
- [x] Data Stacking
- [ ] Data Time Bucketing
