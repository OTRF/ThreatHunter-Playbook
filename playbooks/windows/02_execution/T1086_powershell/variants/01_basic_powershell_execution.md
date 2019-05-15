# Basic PowerShell Execution

## Technique ID(s)

T1086

## Tactic Name(s)

Execution

## Technical Description

Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Therefore, it is important to understand the basic artifacts left when PowerShell is used in your environment.

## Hypothesis

Adversaries might be leveraging PowerShell to execute code within my environment

## Attack Technique Simulation

| Simulation Type | script/file name | Description | Link |
|--------|---------|---------|
| Pre-recorded Data | empire_execution_powershell.json | Mordor-Gates project file |  |

## Recommended Data Sources

| Behavior Identified | Data Source | Log Name | Category | Sub-Category| Event Id |
|---------|---------|---------|---------|---------|---------|
| Process Creation | Microsoft-Windows-Security-Auditing | Security | Detailed Tracking | Process Creation | 4688 |
| Process Creation | Microsoft-Windows-Sysmon | Microsoft-windows-sysmon/operational | Process Created | | 1 |
| Module Loaded | Microsoft-Windows-Sysmon | Microsoft-windows-sysmon/operational | Image Loaded | | 7 |
| Win Pipe Creation | Windows Sysmon | Microsoft-windows-sysmon/operational | Pipe Created | | 17 |
| PowerShell Execution | PowerShell | Windows PowerShell | Engine Lifecycle |  | | 400 |

## Data Analytics

### Goal: Detect execution of PowerShell via modules loaded

| Analytic Engine | Analytic Type | Analytic Logic | Analytic Data Object |
|--------|---------|---------|---------|
| Kibana | Situational Awareness | event_id:7 AND ( file_description:system.management.automation OR module_loaded:\*system.management.automation\* ) | [module](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/module.md) |

### Goal: Detect execution of PowerShell via pipe creation

| Analytic Engine | Analytic Type | Analytic Logic | Analytic Data Object |
|--------|---------|---------|---------|
| Kibana| Situational Awareness | event_id:17 AND pipe_name:"\PSHost*" | [pipe](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/pipe.md) |

### Goal: Execution of PowerShell via ProcessCreate events

| Analytic Engine | Analytic Type | Analytic Logic | Analytic Data Object |
|--------|---------|---------|---------|
| Kibana | Situational Awareness | (event_id:1 OR event_id:4688) AND process_name:powershell.exe OR process_parent_name:powershell.exe | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/process.md) |

### Goal: Detect execution of PowerShel via PowerShell logs

| Analytic Engine | Analytic Type | Analytic Logic | Analytic Data Object |
|--------|---------|---------|---------|
| Kibana | Situational Awareness | event_id:400 AND (powershell_host_name:ConsoleHost OR powershell_host_application:\*powershell.exe\*) | [powershell engine](https://github.com/Cyb3rWard0g/OSSEM/blob/master/common_information_model/powershell_engine.md) |

## Data Quality Assessment

| Data Dimension | Score | Description |
|---------|---------|---------|
| Completeness | | |
| Consistencty | | |
| Timeliness | | |

## Hunter Notes

* Explore the data produced in your lab environment with the analytics above and document what normal looks like from a PowerShell perspective. Then, take your findings and explore your production environment.
* If execution of PowerShell happens all the time in  your environment, I suggest to categorize the data you collect by business unit or department to document profiles more efficiently.

## Hunting Techniques Recommended

- [x] Query Searching
- [x] Data Grouping
- [ ] Data Aggregating
- [x] Data Stacking
- [ ] Data Time Bucketing
