# Indicator Removal on Host
## Technique ID
T1070


## Description
Adversaries may delete or alter generated event files on a host system, including potentially captured files such as quarantined malware. This may compromise the integrity of the security solution, causing events to go unreported, or make forensic analysis and incident response more difficult due to lack of sufficient data to determine what occurred.[Source](https://attack.mitre.org/wiki/Technique/T1070)


## Hypothesis
Adversaries might be deleting event logs using wevutil within my environment.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [Wevutil](https://github.com/redcanaryco/atomic-red-team/blob/16ccafef72580539074b4e92d190a2eed1e74102/atomics/T1070/T1070.md#atomic-test-1---clear--logs)| Uses Windows native wevutil to clear Windows event logs |[atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/16ccafef72580539074b4e92d190a2eed1e74102/atomics/T1070/T1070.md#atomic-test-1---clear--logs) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring| Sysmon |
| Process Monitoring|WinEvent| 


## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 104 | LogName | System OR Setup OR Application | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| WinEvent | 1102 | LogName | Security | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| WinEvent | 104,1102 | TastCategory | Log clear | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| WinEvent | 4688 | NewProcessName | wevutil | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Defense%20Evasion/Indicator_Removal_on_Host.md) |
| WinEvent | 4688 | ProcessCommandLine | wevutil cl | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Defense%20Evasion/Indicator_Removal_on_Host.md) |
| Sysmon | 1 | Image | wevutil | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Defense%20Evasion/Indicator_Removal_on_Host.md) |
| Sysmon | 1 | CommandLine | wevutil cl | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Defense%20Evasion/Indicator_Removal_on_Host.md) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Wevutil | Sysmon Configuration| [T1070_wevutil.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T1070_wevutil.xml)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Situational Awareness|  event WHERE event\_id == "104" OR event\_id == "1102" | <TBD> | 


## Hunter Notes
* You can easily just look or alert(Automating) for events 104 OR 1102. Make sure you understand that 104 gets generated when events get deleted from the SYSTEM windows logs and 1102 when events get deleted from the SECURITY windows logs.
* You could also look for the use of wevutil via Sysmon or native Windows event logs correlating process name wevtil with command argument "cl".


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
