# Indirect Command Execution
## Technique ID
T1202


## Description
Various Windows utilities may be used to execute commands, possibly without invoking cmd. For example, Forfiles, the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a Command-Line Interface, Run window, or via scripts.

Adversaries may abuse these utilities for Defense Evasion, specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of cmd. 

Source: [T1202_Indirect\_Command\_Execution](https://attack.mitre.org/wiki/Technique/T1202)

## Hypothesis
An attacker is using an alternative method to execute code.


## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [forfiles.exe](https://github.com/pwndizzle/CodeExecutionOnWindows)| Forfiles supports the ability to execute commands and seems to be equivalent to cmd. | [pwndizzle](https://github.com/pwndizzle/CodeExecutionOnWindows) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring| Sysmon|
|Process Monitoring|WinEvent| 


## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
|Sysmon | 1 | Image| C:\Windows\System32\cmd.exe | - |
|Sysmon | 1 | Image| C:\Windows\System32\forfiles.exe | - |
|Sysmon | 1 | ParentImage| C:\Windows\System32\forfiles.exe | - |
|Sysmon | 1 | CommandLine| /c, /p, /s, /d  | - |
|Sysmon | 11 | TargetFileame| C:\Windows\Prefetch\FORFILES.EXE-*.pf | - |
|Sysmon | 7 | ImageLoaded| C:\Windows\System32\forfiles.exe | - |
|WinEvent | 4688 | ProcessCommandLine | /c, /p, /s, /d | - |
|WinEvent | 4688 | CreatorProcessName | C:\Windows\System32\forfiles.exe | - |
|WinEvent | 4688 | NewProcessName | C:\Windows\System32\forfiles.exe | - |


 
## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| forfiles.exe | [TBD] | \[TBD\]


## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Situational Awareness | process WHERE process\_parent\_name == "forfiles.exe" AND process\_name == "*"  | [process](https://github.com/bfuzzy/OSSEM/blob/master/detection_data_model/data_objects/process.md) | 

## Hunter Notes
* Look at process creations that include or are resulting from parameters associated with invoking programs/commands and/or spawning child processes


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
