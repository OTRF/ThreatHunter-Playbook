# Acess Token Manipulation 
## Technique ID
 T1134


## Description
Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token. For example, Microsoft promotes the use of access tokens as a security best practice. Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command runas.

Source: [T1134_Access\_Token\_Manipulation](https://attack.mitre.org/wiki/Technique/T1134)

## Hypothesis
Adversaries may use access tokens to operate under a different user or system security context to perform actions and evade detection using [PS Get-System](https://gist.github.com/caseysmithrc/ad9d97bb54484d792572c0523c457d82) .

## Attack Simulation

Getsystem via parent process using powershell and embeded c#

| Script  | Reference | 
|--------|---------|
| . .\Get- System.ps1; [MyProcess]::CreateProcessFromParent((Get-Process lsass).Id,"cmd.exe") | [Casey Smith](https://gist.github.com/caseysmithrc/ad9d97bb54484d792572c0523c457d82) |

## Required Data Sources

| OS  | Event Log | Event ID| Description |
|--------|---------|---------|--------------|
| Windows | Sysmon | 11 | FileCreate  |
| Windows | Sysmon | 10 | Process access | 
| Windows | Sysmon | 1 | Process creation |
| Windows | Security | 4688 | Process creation | 
| Windows | PowerShell | 4103 | Module Logging | 

## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
|Sysmon | 11 | Image| *powershell.exe | - |
|Sysmon | 11 | TargetFilename| C:\Users\\\<user>\AppData\Local\Temp\\*.dll OR *.cmdline | - |
|Sysmon | 10 | SourceImage | *powershell.exe | - |
|Sysmon | 10 | TargetImage | *csc.exe | - |
|Sysmon | 1	| Image | *csc.exe | - |
|Sysmon | 1 | CommandLine | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\<user>\AppData\Local\Temp\\*.cmdline" | - | 
|Sysmon | 1 | ParentImage | *powershell.exe | - | 
|WinEvent | 4688 | NewProcessName | *powershell.exe | - |
|WinEvent | 4688 | NewProcessName | *csc.exe | - | 
WinEvent | 4688 | ProcessCommandLine | "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\<user>\AppData\Local\Temp\\*.cmdline" | - |

## Recommended Configuration(s)
| OS | Title | Description | Reference|
|--------|---------|---------|---------|
| Windows | Event ID 4103 - Module Logging | Detailed logging of all PowerShell command input and output | [Event ID 4103](https://github.com/Cyb3rWard0g/OSSEM/blob/c0bf44fb8c527f6e678c4ff1321814108e024315/data_dictionaries/windows/powershell/event-4103.md)
| Windows | Command Line Process Auditing | Audit information for command line processes | [Microsoft](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)




## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier | File path of the process being spawned/created. Considered also the child or source process | process_name |
| Anomaly/Outlier | The complete path and name of the executable related to the main process in the event. Considered also the child or source process path | process_path |
| Anomaly/Outlier | Arguments which were passed to the executable associated with the main process | process\_command_line |
| Anomaly/Outlier | File path that spawned/created the main process | process\_parent_name |
| Anomaly/Outlier | The complete path and name of the executable related to the the process that spawned/created the main process (child) | process\_parent_path |
| Anomaly/Outlier | Arguments which were passed to the executable associated with the parent process | process\_parent\_command_line |
| Anomaly/Outlier | Name of a file without its full path | file_name |
| Anomaly/Outlier |Full path of a file including the name of the file | file_path |
 






## Hunter Notes
* Detailed command line activity auditing
* Powershell logging


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
