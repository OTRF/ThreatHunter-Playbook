# Abuse of Alternate Signed PowerShell Hosts

## Technique ID(s)

T1086

## Tactic Name(s)

Execution,Lateral Movement

## Description

Adversaries can abuse alternate PowerShell Hosts to evade application whitelisting solutions that block powershell.exe and naive logging based upon traditional PowerShell hosts.

Characteristics of a PowerShell host (Matt Graeber @mattifestation):

* These binaries are almost always C#/.NET .exes/.dlls
* These binaries have System.Management.Automation.dll as a referenced assembly
* These may not always be “built in” binaries

## Hypothesis

Adversaries might be leveraging alternate PowerShell Hosts evading traditional PowerShell hosts logging throughout my environment

## Attack Simulation

### Attack Simulation Requirements

Endpoints Event logging: Enable All (It is difficult to know what you need to enable if you have never tested the specific technique before)

Execution of PowerShell remotely requires:

* Source & destination endpoints to set their network connection profile type to domain or private
* Source & destination endpoints to open the PowerShell console as an Administrator
* Source & destination endpoints to run `Enable-PSRemoting`
* Source endpoint to run `winrm s winrm/config/client '@{TrustedHosts="REMOTE-ENDPOINT-NAME"}'`

### Attack Activity Dataset

| type  | Steps/commands | Description | Author | Link/Reference |
|---------|---------|---------|
| command | `invoke-command -scriptblock {get-process} -Credential username -ComputerName REMOTE-ENDPOINT-NAME` | Remote execution of powershell via PowerShell Console | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) | |

## Recommended Data Sources

| Behavior Identified | Data Source | Log Name | Category | Sub-category | Event Id |
|---------|---------|---------|---------|---------|---------|
| Module Loaded | Microsoft-Windows-Sysmon | Microsoft-windows-sysmon/operational | Image Loaded | | 7 |
| Win Pipe Creation | Windows Sysmon | Microsoft-windows-sysmon/operational | Pipe Created | | 17 |
| PowerShell Execution | PowerShell | Windows PowerShell | Engine Lifecycle |  | | 400 |

### Needed Event Logging Configurations

| Requirement | Details | Reference |
|---------|---------|---------|
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
| Detect execution of PowerShell via modules loaded | Situational Awareness | (modules_loaded OR event_id:7) WHERE file_description:system.management.automation OR module_loaded:\*system.management.automation\* | [module](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/module.md) |
| Detect execution of PowerShell via pipe creation | Situational Awareness | (pipe_create OR event_id:17) WHERE pipe_name:"\PSHost*" | [pipe](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/pipe.md) |
| Detect execution of PowerShell via PowerShell Logs | Source | Situational Awareness | (powershell_logs OR event_id:400) WHERE powershell_host_name:ConsoleHost OR powershell_host_application:\*powershell.exe\* | [powershell engine](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/powershell_engine.md) |

## Hunter Notes

* Explore the data produced in your lab environment with the analytics above and document what normal looks like from a PowerShell perspective. Then, take your findings and explore your production environment.
* If powershell activity locally or remotely via winrm happens all the time in  your environment, I suggest to categorize the data you collect by business unit or department to document profiles.

## Hunting Techniques Recommended

- [x] Query Searching
- [x] Data Grouping
- [ ] Data Aggregating
- [x] Data Stacking
- [ ] Data Time Bucketing