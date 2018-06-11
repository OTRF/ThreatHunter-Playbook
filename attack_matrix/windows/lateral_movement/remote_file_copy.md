# Remote File Copy
## Technique ID
T1105


## Description
Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Adversaries may also copy files laterally between internal victim systems to support Lateral Movement with remote Execution using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with Windows Admin Shares or Remote Desktop Protocol.


## Hypothesis
Adversaries are copying files to $ shares via the command line to facilitate lateral movement.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| \[TBD](TBD)| TBD | \[TBD\](TBD) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
| Process Monitoring|Sysmon|
| Process Monitoring|WinEvent| 
|File Monitoring|Sysmon|
|Object Audit Access (File Share) | Winevent (Security)

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 5145 | ObjectType | File | [Jack Crook](https://t.co/HSykx8LC6V) |
| WinEvent | 5145 | ShareName | *\$ | [Jack Crook](https://t.co/HSykx8LC6V) |
| WinEvent | 5145 | AccessMask | 0x1000180 OR 0x80 OR 0x130197 | [Jack Crook](https://t.co/HSykx8LC6V) |


## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Audit File Share |Audit File Share allows you to audit events related to file shares: creation, deletion, modification, and access attempts. | [Audit File Share](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-share)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Situational Awareness | event WHERE event\_id == "5145" object\_type == "File" share\_name == "*$" AND access\_mask == "0x10018" OR access\_mask == "0x80" OR access\_mask == "0x130197" AND network WHERE src\_host\_name == "\*" | [ip](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/ip.md) | 



## Hunter Notes
* When a file is copied via the command the logs produced are different than if you were to copy them via Windows Explorer. Both methods produce multiple file share access events, but the Access Masks are different depending on method. From the command line, theses are the unique values:
	* 0x100180
	* 0x80
	* 0x130197
* Bucket 3 events within 1 sec by ComputerName
* Jack's Query Example
	* sourcetype=wineventlog:security EventCode=5145 Object_Type=File Share_Name=*$ (Access_Mask=0x100180 OR Access_Mask=0x80 OR Access_Mask=0x130197) |bucket span=1s _time |rex "(?<thingtype>(0x100180|0x80|0x130197))" |stats values(Relative_Target_Name) AS Relative_Target_Name, values(Account_Name) AS Account_Name, values(Source_Address) AS Source_Address, dc(thingtype) AS distinct_things by ComputerName, _time |search distinct_things=3

	
## Hunting Techniques Recommended

- [x] Grouping
- [ ] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
