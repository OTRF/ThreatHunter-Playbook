# Pass-The-Hash
## Description
Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.


## Hypothesis
Adversaries are moving laterally by reusing compromised hashes and authenticating to systems where users have access to. 


## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4776 | PackageName | MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 | Cyb3rWard0g |
| WinEvent | 4624 | Subject.SecurityID | NULL SID OR "S-1-0-0" | Cyb3rWard0g |
| WinEvent | 4624 | LogonType | 3 | Cyb3rWard0g |
| WinEvent | 4624 | WorkstationName | NOT Blank (localSystem) | Cyb3rWard0g |
| WinEvent | 4624 | SourceNetworkAddress/IPAddress | NOT "::1" | Cyb3rWard0g |
| WinEvent | 4624 | LogonProcess | NtLmSsp | Cyb3rWard0g |
| WinEvent | 4624 | LMPackageName | NTLM V2 | Cyb3rWard0g |
| WinEvent | 4624 | KeyLength | 0 | Cyb3rWard0g |
| WinEvent | 4624 | AccountName/TargetUserName | NOT "ANONYMOUS LOGON" | [MITRE CAR](https://car.mitre.org/wiki/CAR-2016-04-004) |


## Hunter Notes
* EID 4776: When a system successfully authenticates a local SAM account via NTLM (instead of Kerberos), the system logs this event. This specifies which user account was used to log on and the computer's name from which the user initiated the logon
* WorkstationName field: look for communications between internal workstations in your network.
* SourceNetworkAddress : Filter out ::1 (local) and you will get mostly IP addresses of other systems in your network.
* KeyLength 0: That reduces th enumber of events. 128 is related to RDP activity.
* Filter out "ANONYMOUS LOGON" - Reduces noise.

	
## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
