# Bypass Application Whitelisting with Odbcconf.exe
## Technique ID
T0000_odbcconf


## Description
ODBCCONF.exe is a command-line tool that allows you to configure ODBC drivers and data source names. It also has two interesting switches "/A and /F". /A allows you to load an arbitrary dll, no injection required this way while /F uses a response file such as "file.rsp" which could also load an arbitrary dll. /F accepts other file extensions. Adversaries may take advantage of this functionality to bypass process whitelisting. 

## Hypothesis
Adversaries might be using odbcconf.exe to load/register dlls and bypass application/process whitelisting controls in my environment

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [odbconf (line 48)](https://github.com/redcanaryco/atomic-red-team/blob/1a9d60f78aa4ebd2fc45bb976476d9d2fd1fa094/Windows/Payloads/AllTheThings/Program.cs)| Loads a psuedo "malicious" dll to test application whitelisting controls | [Casey Smith](https://github.com/redcanaryco/atomic-red-team/blob/1a9d60f78aa4ebd2fc45bb976476d9d2fd1fa094/Windows/Payloads/AllTheThings/Program.cs) |

## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring| Sysmon |
|Process Monitoring|WinEvent| 

## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | Image OR ParentImage | odbcconf.exe | SubTee |
| Sysmon | 1 | CommandLine OR ParentCommandLine | ("/A" AND "REGSVR" AND *.dll) OR "/F"| SubTee |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| odbcconf.exe | Sysmon Configuration | [T0000\_odbcconf.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T0000_odbcconf.xml)


## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Situational Awareness | process WHERE process\_name == "odbconf.exe" AND process\_command\_line == "*"  | [process](https://github.com/bfuzzy/OSSEM/blob/master/detection_data_model/data_objects/process.md) | 

## Hunter Notes
* Subtee talked about adding confusion to command line auditing since this binary can simply register a dll and mimic, for example, powershell functionality and execute commands under a different process name or context. However, the initial registration of the arbitrary binary is what we would focus with this basic combination of events.
* You could simply search for the use of this binary in your environment
* You could also group those two events to find outliers if odbcconf.exe is normal in your environment


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
