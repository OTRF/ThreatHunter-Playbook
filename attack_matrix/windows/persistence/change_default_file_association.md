# Change Default File Association
## Technique ID
T1042


## Description
When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access.12 Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.

System file associations are listed under HKEY\_CLASSES\_ROOT\.[extension], for example HKEY\_CLASSES\_ROOT\.txt. The entries point to a handler for that extension located at HKEY\_CLASSES\_ROOT\[handler]. The various commands are then listed as subkeys underneath the shell key at HKEY\_CLASSES\_ROOT\[handler]\shell\[action]\command. For example:

HKEY\_CLASSES\_ROOT\txtfile\shell\open\command
HKEY\_CLASSES\_ROOT\txtfile\shell\print\command
HKEY\_CLASSES\_ROOT\txtfile\shell\printto\command
The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to execute arbitrary commands. [Source](https://attack.mitre.org/wiki/Technique/T1042)

## Hypothesis
An attacker has compromised a workstation and has changed a file association to execute a malicious program via cmd.


## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [Change default file association](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1042/T1042.md#atomic-test-1---change-default-file-association)| Command prompt is used to change the default file association using a native Windows function. | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1042/T1042.md#atomic-test-1---change-default-file-association) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|File Monitoring| Sysmon, WinEvent |
|Process Monitoring|Sysmon, WinEvent| 
|Registry Monitoring|Sysmon |




## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon| 13 | Image | C:\WINDOWS\system32\cmd.exe | N/A |
| Sysmon | 13 | TargetObject | HKCR\[handler]\shell\open\command\ | N/A |
| Sysmon | 13 | EventType | SetValue | N/A |



## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| N/A | N/A | \[N/A\]



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier |  process WHERE process\_parent\_name == "cmd.exe"  AND process\_parent\_command\_line == "assoc\*" OR process\_parent\_command\_line == "ftype\*" | [process](https://github.com/bfuzzy/OSSEM/blob/master/detection_data_model/data_objects/process.md) | 
| Anomaly/Outlier | event WHERE  event\_id == "13" event\_type == "SetValue" AND process WHERE process\_parent\_name == "cmd.exe" | [process](https://github.com/bfuzzy/OSSEM/blob/master/detection_data_model/data_objects/process.md), [registry](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/registry.md)


## Hunter Notes
* Look for abnormal processes where a registry "SetValue" event occurs listed under HKEY\_CLASSES\_ROOT\.[extension] .


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
