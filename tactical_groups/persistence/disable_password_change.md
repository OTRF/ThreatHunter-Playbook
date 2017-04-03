# Disable Password Change
## Description
Once the attacker has access to the computer account password hash, the account can be used as a “user” account to query Active Directory, but the more interesting use case is to create Silver Tickets to access computer hosted services with admin rights. Since the Domain computer account password change policies are more of a guideline since they aren’t forced to change by the Domain Controllers (set to 30 days by default but up to the computer to actually change the password), it’s possible that once an attacker gains knowledge of the computer account password, it could be used for a long time. Active Directory does not prevent a computer account from accessing AD resources even if the computer account password hasn’t changed in years.

## Hypotheis
Attackers might be updating the DisablePasswordChange registry value to 1 in order to ensure that the machine password would never be changed.

## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 13 | TargetObject | HKLM\System\CurrentControlSet\services\Netlogon\Parameters\DisablePasswordChange | Cyb3Ward0g |
| Sysmon | 13 | Details | DWORD (0x00000001) | Cyb3Ward0g |

## Hunter Notes


## Hunting Techniques Recommended

- [ ] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
