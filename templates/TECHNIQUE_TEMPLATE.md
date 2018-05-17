# Adversary Technique
## Technique ID
T0001_technique_name


## Description


## Hypothesis



## Attack Simulation

[Explanation on how an adversary commonly uses the below technique / script ]

| Script  | Reference | 
|--------|---------|
| Technique command or script | \[Author Name\](link) |



## Required Data Sources

| OS  | Event Log | Event ID| Description |
|--------|---------|---------|--------------|
| Windows, etc | Security | 4688, etc | Process creation |
| Windows, etc | Sysmon | 1 | Process creation |



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



## Required Configuration(s)
\[T0001_technique_name.xml\]\(https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T0001_technique_name.xml\)

OR None



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Behavioral Analytics, Situational Awareness, Anomaly/Outlier | Data Dictionary info...etc | Data Objects... | 


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
