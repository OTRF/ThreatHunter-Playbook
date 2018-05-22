# Acess Token Manipulation 
## Technique ID
 T1134


## Description
Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token. For example, Microsoft promotes the use of access tokens as a security best practice. Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command runas.

Source: [T1134_Access\_Token\_Manipulation](https://attack.mitre.org/wiki/Technique/T1134)

## Hypothesis
Adversaries may use access tokens to operate under a different user or system security context to perform actions and evade detection using [PS Get-System](https://gist.github.com/caseysmithrc/ad9d97bb54484d792572c0523c457d82) .

## Attack Simulation


| Script  | Short Description | Author | 
|---------|---------|---------|
| [Get-System](https://gist.github.com/caseysmithrc/ad9d97bb54484d792572c0523c457d82)| Getsystem via parent process using powershell and embeded c#  | [Casey Smith](https://twitter.com/subTee/status/996853131655958529) |

## Recommended Data Sources

| ATT&CK Data Source | Event Log | 
|---------|---------|
|File Monitoring| Sysmon |
|Process Monitoring| Sysmon |
|Process Monitoring| Security |
|PowerShell Logs| PowerShell | 

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
| Title | Description | Reference|
|---------|---------|---------|
| Event ID 4103 - Module Logging | Detailed logging of all PowerShell command input and output | [Event ID 4103](https://github.com/Cyb3rWard0g/OSSEM/blob/c0bf44fb8c527f6e678c4ff1321814108e024315/data_dictionaries/windows/powershell/event-4103.md)
| Event ID 4104 - Script Block Logging | Detailed logging of script-based activity | [Event ID 4104](https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/)
| Command Line Process Auditing | Audit information for command line processes | [Microsoft](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)




## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier | process\_parent_name = "powershell.exe" AND process\_name = "csc.exe" WHERE file\_path = "C:\Users\\\<user>\AppData\Local\Temp\\" OR file\_name CONTAINS ".dll" OR ".cmdline" | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/c0bf44fb8c527f6e678c4ff1321814108e024315/detection_data_model/data_objects/process.md), [file](https://github.com/Cyb3rWard0g/OSSEM/blob/c0bf44fb8c527f6e678c4ff1321814108e024315/detection_data_model/data_objects/file.md) |
 


## Hunter Notes
* Detailed command line activity auditing
* Powershell logging
* Searches should included encoded commands, remote use of powershell, common injection methods and common execution modules


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
