# EventVwr BypassUAC
## Description
Currently, there are a couple of public UAC bypass techniques, most of which require a privileged file copy using the IFileOperation COM object or WUSA extraction (Windows 7) to take advantage of a DLL hijack in a protected system location. All of these techniques require dropping a file to disk (for example, placing a DLL on disk to perform a DLL hijack). This technique uses eventvwr.exe and hijacked registry keys to elevate privileges. It has been tested on Windows 7 and Windows 10, but is expected to work on all versions of Windows that implement UAC.


## Hypothesis
Adversaries might be leveraging eventvwr.exe to bypass UAC and elevate privileges in the network.


## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 1 | ParentImage | Eventvwr.exe OR (powershell.exe OR cmd.exe) | Cyb3rWard0g & MalwareSoup |
| Sysmon | 1 | Image | Eventvwr.exe OR (powershell.exe OR cmd.exe) | Cyb3rWard0g & MalwareSoup) |
| Sysmon | 1 | CommandLine | Suspicious strings or Images(\<base64\>, powershell.exe, cmd.exe, etc.) | Cyb3rWard0g & MalwareSoup |
| Sysmon | 12, 13 | TargetObject | '\mscfile\shell\open\command\(Default)' | Cyb3rWard0g & MalwareSoup |
| Sysmon | 13 | Details | Suspicious Strings or images (\<base64\>, powershell.exe, cmd.exe, etc.) | Cyb3rWard0g & MalwareSoup |


## Hunter Notes
* Look for suspicious images such as powershell, cmd, rundll32, etc spawning eventvwr.exe and vice-versa.
	* Remember that the processes specified above would catch the most common scenarios. Advanced adversaries can rename processes or use other processes to execute commands.
* You can also hunt for base64 or other suspicious images/modules being executed as part of command line events with eventvwr.exe as a parent.
* Look for creation of registry keys that contain 'mscfile\shell\open\command\' as part of the TargetObject value for EID 12 in order to reduce the number of events and expose potentially suspicious activity related to this privilege escalation technique.
* Look for "Registry value set" (EID 13) events for registry keys that contain 'mscfile\shell\open\command\(Default)' as part of their TargetObject value with suspicious strings (cmd, powershell, .ps1, \<base64\>, etc) as part of their "Details".


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
