# WDigest Downgrade
## Technique ID
T1003


## Description
Windows 8.1 introduced a registry setting that allows for disabling the storage of the user’s logon credential in clear text for the WDigest provider.

(HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential)


## Hypothesis
Adversaries are updating the registry value of \WDigest\UseLogonCredential to 1 in order to grab clear text passwords from memory contents of lsass in my environment.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [Invoke-MimikatzWDigestDowngrade.ps1](https://github.com/samratashok/nishang/blob/master/Gather/Invoke-MimikatzWDigestDowngrade.ps1)| The script forces use of Logon Credentials for Wdigest by adding a registry property.| [Nikhil Mittal](https://twitter.com/nikhil_mitt) |

## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Registry Monitoring| Sysmon |
|Process Monitoring |Sysmon| 
|Process Monitoring | WinEvent | 
|PowerShell Logs| PowerShell |
|Sensitive Privilege Use| Windows Security Auditing |


## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 13 | TargetObject | HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 13 | Details | 1 | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |


## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Wdigest downgrade | Sysmon configuration | [T1003_wdigest.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T1003_wdigest.xml)
|  Audit Sensitive Privilege Use | You will need to enable an Audit Policy of Privilege Use Category -> Sub-category Audit Sensitive Privilege Use | [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4673#security-monitoring-recommendations) |


## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Behavioral|  registry\_key\_path = HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential WHERE registry\_key\_details = > 0 | registry | 


## Hunter Notes
 * Monitor for any changes to the registry key


## Hunting Techniques Recommended

- [ ] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
