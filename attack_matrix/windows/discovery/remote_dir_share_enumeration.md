# Remote Dir $ Share Enumeration
## Technique ID
T1135


## Description
Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.


## Hypothesis
Adversaries are enumerating remote file shares within my environment.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1#L7984)| Execute the NetShareEnum Win32API call to query a given host for open shares. | [@harmjoy](https://twitter.com/harmj0y) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring| Sysmon |
|Object Access | Security|

## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 5145 | ShareName | *c$ OR *ADMIN$ | [Jack Crook](https://t.co/HSykx8LC6V) |
| WinEvent | 5145 | AccessMask | 0x100080 | [Jack Crook](https://t.co/HSykx8LC6V) |
| WinEvent | 5145 | SourceAddress/IPAddress | NOT 127.0.0.1 | [Jack Crook](https://t.co/HSykx8LC6V) |


## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Object Access| Audit Object Access / File Share | [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings#object-access)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Situational Awareness |  network WHERE user\_name == "\*" AND share\_name == "\*c" OR share\_name == "\*ADMIN$" AND src_ip IS NOT 127.0.0.1 AND time\_span == 1 second | [ip](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/ip.md) | 


## Hunter Notes
* Bucket 3 events within 1 sec by ComputerName


## Hunting Techniques Recommended

- [x] Grouping
- [ ] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
