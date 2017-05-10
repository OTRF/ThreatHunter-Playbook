# Remote Execution of Code via Services
## Description
There are several ways to cause code to execute on a remote host. One of the most common methods is via the Windows Service Control Manager (SCM), which allows authorized users to remotely create and modify services. Several tools, such as PsExec, use this functionality. When a client remotely communicates with the Service Control Manager, there are two observable behaviors. First, the client connects to the RPC Endpoint Mapper over 135/tcp. This handles authentication, and tells the client what port the endpoint—in this case the SCM—is listening on. Then, the client connects directly to the listening port on services.exe. If the request is to start an existing service with a known command line, the the SCM process will run the corresponding command.


## Hypothesis
Adversaries are leveraging SCM capabilities to authorize remote creation and modification of services to move laterally within my network.


## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4776 | PackageName | MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 4776 | LogonAccount/TargetUserName | Administrator (RID 500) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 4624 | Subject.SecurityID | NULL SID OR "S-1-0-0" | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 4624 | LogonType | 3 | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 4624 | WorkstationName | NOT Blank (localSystem) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 4624 | SourceNetworkAddress/IPAddress | NOT "::1" | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 4624 | LogonProcess | NtLmSsp | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 4624 | LMPackageName | NTLM V2 | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 4624 | KeyLength | 0 | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 4624 | AccountName/TargetUserName | NOT "ANONYMOUS LOGON" | [MITRE CAR](https://car.mitre.org/wiki/CAR-2016-04-004) |
| WinEvent | 5140 | ShareName | \\*\ADMIN OR \\*\IPC$ OR \\*\C$ | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 5145 | SubjectUserName | NOT a ComputerName$ | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 5145 | RelativeTargetName | svcctl OR .exe OR Outlier | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 5145 | Source Address/IPAddress | NOT (::1 OR localhost) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 18 | PipeName | \ntsvcs | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 12,13 | Image | "C:\\Windows\\system32\\services.exe" OR services.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 12 | TargetObject | "HKLM\\System\\CurrentControlSet\\services\\[New Service]" | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) ||
| Sysmon | 13 | TargetObject | "HKLM\\System\\CurrentControlSet\\services\\" AND (ErrorControl OR Start OR Type OR DisplayName OR ObjectName) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 13 | Details | ("DWORD" AND (0x00000000 OR 0x00000003 OR 0x00000010)) OR Random Service Name OR LocalSystem | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 13 | TargetObject | "HKLM\\System\\CurrentControlSet\\Services\\" AND "ImagePath" | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 13 | Details | Regex /.{35,}/ OR (%COMSPEC% OR /C OR powershell) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| WinEvent | 7045,4697 | Service File Name | Regex /.{35,}/ OR (%COMSPEC% OR /C OR powershell) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 1 | ParentImage | "C:\\Windows\\system32\\services.exe" OR services.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 1 | Image | cmd.exe OR powershell.exe OR suspicious process | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 13 | Image | C:\Windows\system32\services.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 13 | TargetObject | "HKLM\System\CurrentControlSet\services\" AND (Start OR DeleteFlag) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 13 | Details | "DWORD" AND (0x00000004 OR 0x00000001) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 12 | Image | C:\Windows\system32\services.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 12 | EventType | DeleteKey | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |
| Sysmon | 12 | TargetObject | "HKLM\\System\\CurrentControlSet\\services\\[New Service]" | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for_11.html) |


## Hunter Notes
* The adversary needs to authenticate to the victims box before creating a new service containing the stager/payload code.
  * If NTLM Hashes are used, then you should see Pass-The-Hash activity via EID 4624.
* EID 4776: When a system successfully authenticates a local SAM account via NTLM (instead of Kerberos), the system logs this event. This specifies which user account was used to log on and the computer's name from which the user initiated the logon.
  * This is to look for RID 500 accounts moving laterally via this technique.
* All the activity from EID 4624 is covered in this same tactical group under ["Pass-The-Hash"](https://github.com/VVard0g/ThreatHunter-Playbook/blob/master/tactical_groups/lateral_movement/pass_the_hash.md).
* EID 5140/5145: You will usually see File Shares being accessed (\\*\IPC$ OR \\*\ADMIN$ OR \\*\C$)
  * SubjectUserName field usually has a computer name. Filter those out.
  * Source Address: Look for remote connections or other systems in your network
  * RelativeTargetName: This field gives you more information about the specific object on the share.
* EID 18 Named Pipes: \ntsvcs usually for creation of services.
* If you want to catch suspicious long strings (most likely a script) or commands as part of services' properties, you can use a basic regex combination to look for strings longer than 45-50 characters (up to you) or known commands. 
	* Sysmon EID 13 catches suspicious scripts or long commands being set to services in HKLM\\System\\CurrentControlSet\\Services\\.
		* On the "Details" field, look for long strings (i.e. more than 35 characters) or known commands.
		* On the "TargetObject" field, you can reduce the number of events by looking for the "ImagePath" reg key where scripts or long commands are usually set.
	* WinEvent EIDs 7045,4697 catch suspicious scripts or long commands being set to "Service File Name".
 * Adversaries at the end usually delete the random services they create so looking for "DeleteKey" events in the same 1-2 seconds bucket time when the same service is created could be interesting.
 * Group all those events and apply a bucket time of 1-2 seconds and see how many systems show that behavior.
 * You can start by checking long strings being set by services.exe on ImagePath properties of new or current services. This will allow you to pivot to other events in the list shown above.
 * You could also stack new services being created in your environment to find any anomalies and start from there.
 

## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
