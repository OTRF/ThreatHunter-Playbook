# Remote PowerShell Sessions
## Technique ID
T1028\_remote\_powershell


## Description
PowerShell can be used over WinRM to remotely run commands on a host. When a remote PowerShell session starts, svchost.exe executes wsmprovhost.exe.


## Hypothesis
Adversaries are moving laterally within my network through remote PowerShell sessions. 

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [PowerShell lateral movement](https://github.com/redcanaryco/atomic-red-team/blob/20a447e63de9d5ef836534743c6f8fdef16c5874/atomics/T1028/T1028.md#atomic-test-2---powershell-lateral-movement)| Powershell lateral movement using the mmc20 application com object | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/20a447e63de9d5ef836534743c6f8fdef16c5874/atomics/T1028/T1028.md#atomic-test-2---powershell-lateral-movement) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring| Sysmon|
|Process Monitoring| WinEvent|  


## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | Image | wsmprovhost.exe | [MITRE CAR](https://car.mitre.org/wiki/CAR-2014-11-004) |
| Sysmon | 1 | ParentImage | svchost.exe | [MITRE CAR](https://car.mitre.org/wiki/CAR-2014-11-004) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
|remote powershell | Sysmon configuration | [T1028\_remote\_powershell.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T1028_remote_powershell.xml)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
|  Situational Awareness |  process\_name = "wsmprovhost.exe" COUNT BY dst\_host\_name | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/process.md), [ip](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/ip.md) | 



## Hunter Notes
* Pretty straightforward combination of events.
* wsmprovhost.exe is present only when the remote PowerShell session is active. As soon as the session stops, wsmprovhost.exe exits. 


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
