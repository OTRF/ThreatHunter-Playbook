# Remote PowerShell Sessions
## Description
PowerShell can be used over WinRM to remotely run commands on a host. When a remote PowerShell session starts, svchost.exe executes wsmprovhost.exe.


## Hypothesis
Adversaries are moving laterally within my network through remote PowerShell sessions. 


## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | Image | wsmprovhost.exe | [MITRE CAR](https://car.mitre.org/wiki/CAR-2014-11-004) |
| Sysmon | 1 | ParentImage | svchost.exe | [MITRE CAR](https://car.mitre.org/wiki/CAR-2014-11-004) |


## Hunter Notes
* Pretty straightforward combination of events.
* wsmprovhost.exe is present only when the remote PowerShell session is active. As soon as the session stops, wsmprovhost.exe exits. 


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting