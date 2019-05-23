# Local Port Monitor
## Technique ID
T1013


## Description
A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup. This DLL can be located in C:\Windows\System32 and will be loaded by the print spooler service, spoolsv.exe, on boot. Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors. The spoolsv.exe process also runs under SYSTEM level permissions.


## Hypothesis
Adversaries are creating persistence in my network by leveraging the process of setting up a local port monitor and executing code at startup. 

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| \[TBD\](TBD)| TBD | \[TBD\](TBD) |


## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|File Monitoring| Sysmon |
|Registry Monitoring|Sysmon|

## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 12 | TargetObject | HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\[New Key]\\Driver | [Brady Bloxham](https://www.youtube.com/watch?v=dq2Hv7J9fvk) |
| Sysmon | 13 | TargetObject | HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\[New Key]\\Driver | [Brady Bloxham](https://www.youtube.com/watch?v=dq2Hv7J9fvk) |
| Sysmon | 13 | Details | Value set to a dll name| [Brady Bloxham](https://www.youtube.com/watch?v=dq2Hv7J9fvk) |
| Sysmon | 11 | TargetFileName | Pivot from dll in regkey value "Driver" | [Brady Bloxham](https://www.youtube.com/watch?v=dq2Hv7J9fvk) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| localport\_monitor | Sysmon configuration | [T1013\_localport\_monitor.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/TT1013_localport_monitor.xml)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier |  TBD  | [file](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/file.md), [registry](TBD) | 



## Hunter Notes
* Combination of EIDs will reduce the number of false positives; pivoting from files created under System32 directory to registry values being set.
	* If this is something that you see often in your environment, then stack the values of Registry keys being created under HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\ and the values being set to "Drivers".
* Stack DLLs being written or created under the System32 directory and check for outliers against known/whitelisted modules. It could be a good start for this hunt.


## Hunting Techniques Recommended

- [ ] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests