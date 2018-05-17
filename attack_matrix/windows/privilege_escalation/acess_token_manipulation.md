# Acess Token Manipulation 
## Technique ID
 T1134


## Description
Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token. For example, Microsoft promotes the use of access tokens as a security best practice. Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command runas.

Source: [T1134_Access\_Token\_Manipulation](https://attack.mitre.org/wiki/Technique/T1134)

## Hypothesis
Adversaries may use access tokens to operate under a different user or system security context to perform actions and evade detection using [PS Get-System](https://gist.github.com/caseysmithrc/ad9d97bb54484d792572c0523c457d82) . 

## Events

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


 



## Atomic Sysmon Configuration

None


## Hunter Notes
* Detailed command line activity auditing
* Powershell logging
* Odd process relations


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
