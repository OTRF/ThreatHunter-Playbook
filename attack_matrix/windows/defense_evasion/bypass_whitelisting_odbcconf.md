# Bypass Application Whitelisting with Odbcconf.exe
## Technique ID
T0000_odbcconf


## Description
ODBCCONF.exe is a command-line tool that allows you to configure ODBC drivers and data source names. It also has two interesting switches "/A and /F". /A allows you to load an arbitrary dll, no injection required this way while /F uses a response file such as "file.rsp" which could also load an arbitrary dll. /F accepts other file extensions. Adversaries may take advantage of this functionality to bypass process whitelisting. 

## Hypothesis
Adversaries might be using odbcconf.exe to load/register dlls and bypass application/process whitelisting controls in my environment


## Events.

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | Image OR ParentImage | odbcconf.exe | SubTee |
| Sysmon | 1 | CommandLine OR ParentCommandLine | ("/A" AND "REGSVR" AND *.dll) OR "/F"| SubTee |


## Atomic Sysmon Configuration
[T0000_odbcconf.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T0000_odbcconf.xml)


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
