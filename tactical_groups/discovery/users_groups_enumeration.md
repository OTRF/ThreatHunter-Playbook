# Users and Groups Enumeration
## Description
Enumerating users and groups is very useful to an adversary. Knowing usernames and the names of groups can come handy. As an attacker, you want to grab as much as you can, after all, this is the reconnaissance phase.

## Hypothesis
Adversaries are enumerating users and group in the network with the help of net.exe and powershell scripts.

## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| WinEvent | 4661 | ObjectType | SAM_GROUP (When querying Domain Admin groups) | Cyb3rWard0g |
| WinEvent | 4661 | ObjectType | SAM_USER (When querying DCs local accounts and Domain Admins) | Cyb3rWard0g |
| WinEvent | 4661 | SubjectSecurityID | NOT (System OR S-1-5-18) | Cyb3rWard0g |
| WinEvent | 4661 | ObjectName | S-1-5-21domain-500 (Domain Local Administrator) | Cyb3rWard0g |
| WinEvent | 4661 | ObjectName | S-1-5-21domain-502 (KRBTGT) | Cyb3rWard0g |
| WinEvent | 4661 | ObjectName | S-1-5-21domain-512 (Domain Admins Group) | Cyb3rWard0g |
| WinEvent | 4661 | ObjectName | S-1-5-21domain-516 (Domain Controllers Group) | Cyb3rWard0g |
| WinEvent | 4661 | ObjectName | S-1-5-21domain-519 (Enterprise Admins Group) | Cyb3rWard0g |
| WinEvent | 4661 | AccessMask | 0xF01BF (Requestor has Domain Admin Rights) | Cyb3rWard0g |
| WinEvent | 4661 | AccessMask | 0x20094 (Requestor has Standard Domain User Rights) | Cyb3rWard0g |


## Hunter Notes
* EID 4661 events are generated on Domain Controllers (Target)
* Looking for Object Type SAM_GROUP and Objet Names related to Admin groups is really suspicious specially when the handle to the object is not being made by the DC itself.
* Same for Domain Admin and KRBTGT accounts.
* Access Mask 0x20094 is from a regular domain user account.
* Access Mask 0xF01BF is from users with Domain Admin rights.

## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
