# Indirect Command Execution
## Technique ID
T1202


## Description
Various Windows utilities may be used to execute commands, possibly without invoking cmd. For example, Forfiles, the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a Command-Line Interface, Run window, or via scripts.

Adversaries may abuse these utilities for Defense Evasion, specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of cmd. 

Source: [T1202_Indirect\_Command\_Execution](https://attack.mitre.org/wiki/Technique/T1202)

## Hypothesis
An attacker is using an alternative method to execute code.

## Events

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


 



## Atomic Sysmon Configuration

None


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
