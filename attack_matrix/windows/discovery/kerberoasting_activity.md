# Kerberoasting Activity
## Technique ID
T0000_Kerberoasting


## Description
Kerberoasting can be an effective method for extracting service account credentials from Active Directory as a regular user without sending any packets to the target system. This attack is effective since people tend to create poor passwords. The reason why this attack is successful is that most service account passwords are the same length as the domain password minimum (often 10 or 12 characters long) meaning that even brute force cracking doesn’t likely take longer than the password maximum password age (expiration). Most service accounts don’t have passwords set to expire, so it’s likely the same password will be in effect for months if not years. Furthermore, most service accounts are over-permissioned and are often members of Domain Admins providing full admin rights to Active Directory (even when the service account only needs to modify an attribute on certain object types or admin rights on specific servers).


## Hypothesis
Adversaries might be obtaining/requesting Kerberos service ticket(s) (TGS) for the Service Princial Name (SPN) of service accounts in my environment.


## Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4769 | TicketOptions | 0x40810000 | [@SeanMetcalf](https://adsecurity.org/?p=3458) |
| WinEvent | 4769 | TicketEncryptionType | 0x17 | [@SeanMetcalf](https://adsecurity.org/?p=3458) |
| WinEvent | 4769 | ClientAddress/IPAddress | NOT ::1 | [Cyb3Ward0g](https://twitter.com/Cyb3rWard0g) |
| WinEvent | 4769 | ServiceName | NOT *$ | [Cyb3Ward0g](https://twitter.com/Cyb3rWard0g) |


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
