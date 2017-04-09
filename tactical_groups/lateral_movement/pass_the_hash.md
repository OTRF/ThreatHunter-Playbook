# Pass-The-Hash
## Description
Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.


## Hypothesis
Adversaries are moving laterally by reusing compromised hashes and authenticating to systems where users have access to. 


## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4624 | Subject.SecurityID | NULL SID | Cyb3rWard0g |
| WinEvent | 4624 | LogonType | 3 | Cyb3rWard0g |
| WinEvent | 4624 | WorkstationName | NOT Blank (localSystem) | Cyb3rWard0g |
| WinEvent | 4624 | SourceNetworkAddress | NOT "::1" | Cyb3rWard0g |
| WinEvent | 4624 | LogonProcess | NtLmSsp | Cyb3rWard0g |
| WinEvent | 4624 | KeyLength | 0 | Cyb3rWard0g |
| WinEvent | 4624 | AccountName/TargetUserName | NOT "ANONYMOUS LOGON" | [MITRE CAR](https://car.mitre.org/wiki/CAR-2016-04-004) |
| WinEvent | 7035,4697 | Service File Name | Regex /.{35,}/ OR (%COMSPEC% OR /C OR powershell) | Cyb3rWard0g |
| Sysmon | 13 | TargetObject | "HKLM\\System\\CurrentControlSet\\Services\\" AND "ImagePath" | Cyb3rWard0g |
| Sysmon | 13 | Details | Regex /.{35,}/ OR (%COMSPEC% OR /C OR powershell) | Cyb3rWard0g |
| Sysmon | 13 | Image | services.exe | Cyb3rWard0g |


## Hunter Notes
* WorkstationName field: look for communications between internal workstations in your network.
* SourceNetworkAddress : Filter out ::1 (local) and you will get mostly IP addresses of other systems in your network.
* KeyLength 0: That reduces th enumber of events. 128 is related to RDP activity.
* "ANONYMOUS LOGON" : Reduces noise
* There are several ways to cause code to execute on a remote host. One of the most common methods is via the Windows Service Control Manager (SCM), which allows authorized users to remotely create and modify services. Several tools, such as PsExec, CobalStrike, Invoke-Thehash, etc. use this functionality.
* If you want to catch suspicious long strings (most likely a script) or commands as part of Services' properties, you can use a basic regex combination to look for strings longer than 35-45 characters (up to you) or known commands. 
	* Sysmon EID 13 catch suspicious scripts or long commands being set to services in HKLM\\System\\CurrentControlSet\\Services\\.
		* On the "Details" field, look for long strings (i.e. more than 35 characters) or known commands.
		* On the "TargetObject" field, you can reduce the number of events by looking for the "ImagePath" reg key where scripts or long commands are usually set.
	* WinEvent EID 7035,4697 catch suspicious scripts or long commands being set to "Service File Name"

	
## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
