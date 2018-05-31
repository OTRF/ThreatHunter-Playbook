# Disable Password Change
## Technique ID
T0000\_disable\_password\_change


## Description
Once the attacker has access to the computer account password hash, the account can be used as a “user” account to query Active Directory, but the more interesting use case is to create Silver Tickets to access computer hosted services with admin rights. Since the Domain computer account password change policies are more of a guideline since they aren’t forced to change by the Domain Controllers (set to 30 days by default but up to the computer to actually change the password), it’s possible that once an attacker gains knowledge of the computer account password, it could be used for a long time. Active Directory does not prevent a computer account from accessing AD resources even if the computer account password hasn’t changed in years.


## Hypothesis
Attackers might be updating the DisablePasswordChange registry value to 1 in order to ensure that the machine password would never be changed and maintain persistence.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| \[TBD\](TBD)| TBD | \[TBD\](TBD) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Registry Monitoring| Sysmon|

## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 13 | TargetObject | HKLM\System\CurrentControlSet\services\Netlogon\Parameters\DisablePasswordChange | Cyb3Ward0g |
| Sysmon | 13 | Details | DWORD (0x00000001) | Cyb3Ward0g |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| disable\_password\_change | Sysmon configuration | [T0000\_disable\_password\_change.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T0000_disable_password_change.xml)


## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
|  Anomaly/Outlier |  TBD | [registry]\(TBD\) | 


## Hunter Notes
* Look for changes to the registry key specified above.


## Hunting Techniques Recommended

- [ ] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
