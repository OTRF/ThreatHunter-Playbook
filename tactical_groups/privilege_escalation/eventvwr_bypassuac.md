# EventVwr BypassUAC
## Description
Currently, there are a couple of public UAC bypass techniques, most of which require a privileged file copy using the IFileOperation COM object or WUSA extraction (Windows 7) to take advantage of a DLL hijack in a protected system location. All of these techniques require dropping a file to disk (for example, placing a DLL on disk to perform a DLL hijack). This technique uses eventvwr.exe and hijacked registry keys to elevate privileges. It has been tested on Windows 7 and Windows 10, but is expected to work on all versions of Windows that implement UAC.

## Hypotheis
Adversaries might be leveraging eventvwr.exe to bypass UAC and elevate privileges in the network.

## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 1 | ParentImage | Eventvwr.exe OR (powershell.exe OR cmd.exe) | Cyb3rWard0g & MalwareSoup |
| Sysmon | 1 | Image | Eventvwr.exe OR (powershell.exe OR cmd.exe) | Cyb3rWard0g & MalwareSoup) |
| Sysmon | 1 | CommandLine | powershell, cmd.exe -enc, \<base64\> | Cyb3rWard0g & MalwareSoup |
| Sysmon | 12, 13 | TargetObject | '\mscfile\shell\open\command\(Default)' OR '\\mscfile\\' | Cyb3rWard0g & MalwareSoup |


## Hunter Notes
* Look for suspicious images such as powershell, cmd, rundll32, etc spawning eventvwr.exe and vice-versa
* Look for base64 or other suspicious images being executed as part of command line events with eventvwr.exe as a parent
* Creation of registry keys that contain 'mscfile\shell\open\command\' on their names or at least '\mscfile\' by non eventvwr.exe images
* Registry value set events on registry keys that contain 'mscfile\shell\open\command\(Default)' on their names with suspicious values (cmd, powershell, .ps1, \<base64\>, etc) by non eventvwr.exe images.

## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
