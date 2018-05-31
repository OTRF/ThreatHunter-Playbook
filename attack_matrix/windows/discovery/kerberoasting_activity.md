# Kerberoasting Activity
## Technique ID
T1208


## Description
Kerberoasting can be an effective method for extracting service account credentials from Active Directory as a regular user without sending any packets to the target system. This attack is effective since people tend to create poor passwords. The reason why this attack is successful is that most service account passwords are the same length as the domain password minimum (often 10 or 12 characters long) meaning that even brute force cracking doesn’t likely take longer than the password maximum password age (expiration). Most service accounts don’t have passwords set to expire, so it’s likely the same password will be in effect for months if not years. Furthermore, most service accounts are over-permissioned and are often members of Domain Admins providing full admin rights to Active Directory (even when the service account only needs to modify an attribute on certain object types or admin rights on specific servers).


## Hypothesis
Adversaries might be obtaining/requesting Kerberos service ticket(s) (TGS) for the Service Princial Name (SPN) of service accounts in my environment.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [Invoke-Kerberoast](Lhttps://github.com/malachitheninja/Invoke-Kerberoast/blob/master/Invoke-Kerberoast.ps1)| Requests service tickets and returns crackable ticket hashes. | [@harmj0y](https://twitter.com/harmj0y) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Windows Event Logs|WinEvent|


## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4769 | TicketOptions | 0x40810000 | [@SeanMetcalf](https://adsecurity.org/?p=3458) |
| WinEvent | 4769 | TicketEncryptionType | 0x17 | [@SeanMetcalf](https://adsecurity.org/?p=3458) |
| WinEvent | 4769 | ClientAddress/IPAddress | NOT ::1 | [Cyb3Ward0g](https://twitter.com/Cyb3rWard0g) |
| WinEvent | 4769 | ServiceName | NOT *$ | [Cyb3Ward0g](https://twitter.com/Cyb3rWard0g) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Audit Kerberos Service Ticket Operations | Events are generated every time Kerberos is used to authenticate a user who wants to access a protected network resource. Kerberos service ticket operation audit events can be used to track user activity. | [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-service-ticket-operations)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier |  event\_id = "4769" AND ticket\_encryption\_type = "0x17" WHERE service\_name IS NOT "*$"    | [TBD] | 

## Atomic Sysmon Configuration
None


## Hunter Notes
* Filter out service accounts (Account Name) & Computers (Service Name).
	* Any service account requesting the TGS
	* Any Service name with the "$" in its name which are typically for computer accounts (Or trusts or Managed Service Accounts, all accounts where Windows automatically generates a long, complex password)
* Inter-Forest tickets use RC4 unless configured to use AES
* ADFS also uses RC4
* Filter on Audit Success


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
