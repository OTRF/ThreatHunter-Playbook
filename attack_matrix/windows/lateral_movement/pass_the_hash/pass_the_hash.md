# Pass-The-Hash
##Technique ID
T1075


## Description
Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.


## Hypothesis
Adversaries are moving laterally by reusing compromised hashes and authenticating to systems where users have access to. 

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [Mimikatz PtH](https://github.com/redcanaryco/atomic-red-team/blob/0b4e8725bd845db926d8f7f8faa1505393916037/atomics/T1075/T1075.md#atomic-test-1---mimikatz-pass-the-hash)|  Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems. | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/0b4e8725bd845db926d8f7f8faa1505393916037/atomics/T1075/T1075.md#atomic-test-1---mimikatz-pass-the-hash) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Authentication Logs|  WinEvent |




## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4776 | PackageName | MICROSOFT\_AUTHENTICATION\_PACKAGE\_V1\_0 | Cyb3rWard0g |
| WinEvent | 4776 | LogonAccount/TargetUserName | Administrator (RID 500) | Cyb3rWard0g |
| WinEvent | 4624 | Subject.SecurityID | NULL SID OR "S-1-0-0" | Cyb3rWard0g |
| WinEvent | 4624 | LogonType | 3 | Cyb3rWard0g |
| WinEvent | 4624 | WorkstationName | NOT Blank (localSystem) | Cyb3rWard0g |
| WinEvent | 4624 | SourceNetworkAddress/IPAddress | NOT "::1" | Cyb3rWard0g |
| WinEvent | 4624 | LogonProcess | NtLmSsp | Cyb3rWard0g |
| WinEvent | 4624 | LMPackageName | NTLM V2 | Cyb3rWard0g |
| WinEvent | 4624 | KeyLength | 0 | Cyb3rWard0g |
| WinEvent | 4624 | AccountName/TargetUserName | NOT "ANONYMOUS LOGON" | [MITRE CAR](https://car.mitre.org/wiki/CAR-2016-04-004) |


## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| N/A | N/A | \[N/A\](N/A)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Situational Awareness |  TBD  | TBD | 


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
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
