# Pass-The-Hash
## Description
Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.
Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.

## Hypothesis
Adversaries are moving laterally by reusing compromised hashes and authenticating to systems where users have access to. 

## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4624 | Subject.SecurityID | NULL SID | Cyb3rWard0g |
| WinEvent | 4624 | LogonType | 3 | Cyb3rWard0g |
| WinEvent | 4624 | WorkstationName | NOT Blank (localSystem) AND Another System in the network | Cyb3rWard0g |
| WinEvent | 4624 | SourceNetworkAddress | NOT ::1 | Cyb3rWard0g |
| WinEvent | 4624 | LogonProcess | NtLmSsp | Cyb3rWard0g |
| WinEvent | 4624 | KeyLength | 0 (Excluding other sessions) | Cyb3rWard0g |
| WinEvent | 7035 | Service File Name | %COMSPEC% OR /C OR powershell (OPTIONAL) | Cyb3rWard0g |


## Hunter Notes


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
