# Adversary Technique
## Technique ID
T0001_technique_name


## Description


## Hypothesis



## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| \[Link to script\](Link)| Short description on how an attacker would use the script or techniquie  | \[Author Name\](Link) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log | Event ID| Description |
|---------|---------|---------|--------------|
|File Monitoring, Process Monitoring, etc..| Sysmon, WinEvent, PowerShell | ID | FileCreate, Process access, etc..  |
|File Monitoring, Process Monitoring, etc..|Sysmon, WinEvent, PowerShell | ID | FileCreate, Process access, etc.. | 
|File Monitoring, Process Monitoring, etc..|Sysmon, WinEvent, PowerShell | ID | FileCreate, Process access, etc.. | 
|File Monitoring, Process Monitoring, etc..| Sysmon, WinEvent, PowerShell | ID | FileCreate, Process access, etc.. |
|File Monitoring, Process Monitoring, etc..| Sysmon, WinEvent, PowerShell | ID | FileCreate, Process access, etc.. | 
|File Monitoring, Process Monitoring, etc..| Sysmon, WinEvent, PowerShell | ID | FileCreate, Process access, etc.. | 



## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon, WinEvent, PowerShell | ID | Field, ALL | Short Description or Strings | \[Author Name\](link) |
| Sysmon, WinEvent, PowerShell | ID | Field, ALL | Short Description or Strings | \[Author Name\](link) |
| Sysmon, WinEvent, PowerShell | ID | Field, ALL | Short Description or Strings | \[Author Name\](link) |
| Sysmon, WinEvent, PowerShell | ID | Field, ALL | Short Description or Strings | \[Author Name\](link) |
| Sysmon, WinEvent, PowerShell | ID | Field, ALL | Short Description or Strings | \[Author Name\](link) |
| Sysmon, WinEvent, PowerShell | ID | Field, ALL | Short Description or Strings | \[Author Name\](link) |
| Sysmon, WinEvent, PowerShell | ID | Field, ALL | Short Description or Strings | \[Author Name\](link) |
| Sysmon, WinEvent, PowerShell | ID | Field, ALL | Short Description or Strings | \[Author Name\](link) |



## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Example: Event ID 4103 - Module Logging | Example: Detailed logging of all PowerShell command input and output | \[Event ID 4103\](link)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Behavioral Analytics, Situational Awareness, Anomaly/Outlier | Example: process\_parent_name = "powershell.exe" AND process\_name = "csc.exe" WHERE file\_path = "C:\Users\\\<user>\AppData\Local\Temp\\" OR file\_name CONTAINS ".dll" OR ".cmdline" | Data Objects... | 


## Hunter Notes
* Notes..


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
