# Bypass Application Whitelisting with IEExec.exe
## Technique ID
T0000_ieexec


## Description
The IEExec.exe application is an undocumented Microsoft .NET Framework application that is included with the .NET Framework. You can use the IEExec.exe application as a host to run other managed applications that you start by using a URL. [Source](https://support.microsoft.com/en-us/help/822485/how-to-debug-managed-client-applications-that-are-started-by-using-a-url-in-visual-studio-net-or-in-visual-studio-2005). First, the adversary needs to disable code access security in the victim's computer. This can be acomplished by using the Code Access Security Policy Tool (CasPol.exe). This tool allows users and administrators to change the security policies for the policy level of the computer, the user, and the organization. [Source](https://msdn.microsoft.com/en-us/library/cb6t8dtz(v=vs.100).aspx)


## Hypothesis
Adversaries might be bypassing application whitelisting controls within my organization by levaring IEExec.exe to execute remote malicious binaries and caspol.exe to disable code access security.  


## Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent| 4688 | NewProcessName | *CasPol.exe | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 1 | Image | *CasPol.exe | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 1 | CommandLine | *CasPol.exe AND "-s off" | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 10 | TargetImage | *CasPol.exe | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 10 | CallTrace | *CorperfmontExt.dll* | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| WinEvent | 4688 | NewProcessName | *IEExec.exe | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 1, 7, 12 | Image | *IEExec.exe | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 1 | CommandLine | *IEExec.exe AND http* | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 7 | ImageLoaded | winhttp.dll OR '\AppData\Local\Microsoft\Windows\Temporary Internet Files\' | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 10 | TargetImage | *IEExec.exe | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 12 | TargetObject | HKLM\System\CurrentControlSet\services\Tcpip\Parameters | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 3 | Image | *IEExec.exe | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 3 | DestinationIP | NOT Whitelisted IPs | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |


## Atomic Sysmon Configuration
[T0000_ieexec.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T0000_ieexec.xml)


## Hunter Notes
* You could start looking for an adeversary disabling code access security.
  * The specific command to accomplish this is "caspol.exe -s off" OR "caspol.exe -security off"
  * Stacking the values of caspol.exe could help you to spot all the commands used with that MS binary
* Finding utilization of caspol.exe and IEExec.exe in logs besides Windows event 4688 and Sysmon event 1 can be done via Sysmon events 10 & 7
* One particular event that repeats several times after the adversay disables code access security is Sysmon event 10 with the string "CorperfmontExt.dll" in the CallTrace field
  * CORPerfMonExt.dll, also written as Microsoft Common Language Runtime – Performance Counter DLL, is used to support CasPol, CasPol.exe and csc, csc.exe for Windows 7, Windows 8, Windows Vista and Windows XP, including 32 and 64 bits operating systems.
* Looking for IEExec.exe downloading a remote binary is recorded by Sysmon event 3.
  * You should have a whitelist of IP addresses. Use it against the DestinationIP values of IEExec.exe connecting to.
* Remote communications of IEExec.exe is also recorded by Sysmon events 7 and 12
  * Sysmon EID 7: You can look for "winhttp.dll" OR/AND anything in the 'Windows\temporary Internet Files\' loaded by IEExec.exe
  * Sysmon EID 12: Clear indicator of network communications is the creation of the registry key  HKLM\System\CurrentControlSet\services\Tcpip\Parameters



## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
