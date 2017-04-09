# Remote Desktop Logon
## Description
A remote desktop logon, through RDP, may be typical of a system administrator or IT support, but only from select workstations. Monitoring remote desktop logons and comparing to known/approved originating systems can detect lateral movement of an adversary.


## Hypothesis
Adversaries are moving laterally within my network through RDP connections. 


## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4624 | AuthenticationPackageName | Negotiate | Cyb3rWard0g |
| WinEvent | 4624 | LogonType | 10 | Cyb3rWard0g |
| WinEvent | 4624 | ProcessName | C:\Windows\System32\winlogon.exe | Cyb3rWard0g |
| WinEvent | 4624 | LogonProcessName | User32 | Cyb3rWard0g |
| WinEvent | 4624 | Severity/Level | Information | Cyb3rWard0g |
| WinEvent | 4776 | PackageName | MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 (Local Accounts) | Cyb3rWard0g |
| WinEvent | 4776, 4624 | LogonAccount/TargetUserName | Administrator (Using RID-500) | Cyb3rWard0g |
| Sysmon | 12 | Image | "C:\\Windows\\system32\\LogonUI.exe" | Cyb3rWard0g |
| Sysmon | 12 | TargetObject | "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" | Cyb3rWard0g |


## Hunter Notes
* Basic combination of events to detect RDP activity.
* Logon type 10 (RemoteInteractive): Terminal Services session that is both remote and interactive.
* EID 4776 package name MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 happens when the account used to create the RDP session is a local account and not a domain one.
* EID 4776 OR 4624 Logon Account/Target user name "Administrator" could help to hunt for RDP sessions using the built-in administrator account.
* EID 12 can be used to look for specific registry keys related to Terminal Services being used on an endpoint.
* You can correlate all those events with a time window of 1-3 seconds to reduce the number of false positives when hunting for RDP sessions being created in your environment.
* All these events get created on the target system.


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting