# In-Memory Mimikatz OverPass-The-Hash
##Technique ID
T1075\_mimikatz\_inmem\_pth


## Description
Mimikatz can perform the well-known operation 'Pass-The-Hash' to run a process under another credentials with NTLM hash of the user's password, instead of its real password. When the user logs in, Windows creates a long term key for each encryption method supported by the client OS before requesting/obtaining the TGT. Multiple encryption types are normally available. The client should choose the strongest mutually-supported encryption type, but of course an attacker can produce a downgrade attack to choose weaker encryption.Windows 7 systems support the newer AES. However, it can also still support older RC4 algorithms. As we know, Microsoft uses the NT (NTLM) hash for Kerberos RC4 encryption which is why this attack is very easy to do. All it takes is to inject the compromised NTLM hash into a new process, downgrade the level of encryption to RC4 and obtain a TGT. 

## Hypothesis
Adversaries might be using mimikatz to perform an OverPass-the-Hash technique downgrading the encryption algorithm used to request and obtain TGTs in order to move laterally in the network. Abusing Kerberos authentication.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [mimikatz](https://github.com/gentilkiwi/mimikatz)| Credential dumper | [Benjamin Delpy](http://blog.gentilkiwi.com/) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
| Process Monitoring| Sysmon|
| Process Monitoring |WinEvent | 
|Sensitive Privilege Use| Windows Security Auditing |



## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| WinEvent | 4624 | LogonType 9 | "NewCredentials" | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for.html) |
| WinEvent | 4648 | Subject.SecurityID AND AccountName | "A logon was attempted using explicit credentials" | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for.html) |
| WinEvent | 4768 | TicketEncryptionType | Hex value: 0x17. Encryption Type downgrade behavior captured by the Domain Controller | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for.html) |
| Sysmon | 10 | GrantedAccess | (0x1010 OR 0x1410) AND 0x1038 | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for.html) | 


## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Mimikatz in memory pass-the-hash | Sysmon Configuration | [T1075\_mimikatz\_inmem\_pth.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T1075_mimikatz_inmem_pth.xml)
|  Audit Sensitive Privilege Use | You will need to enable an Audit Policy of Privilege Use Category -> Sub-category Audit Sensitive Privilege Use | [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4673#security-monitoring-recommendations) |



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier | target\_process\_name = "lsass.exe" AND process\_granted\_access = "*" COUNT BY process\_name  | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/c0bf44fb8c527f6e678c4ff1321814108e024315/detection_data_model/data_objects/process.md) |


## Hunter Notes
* EID 4624 Logon Type 9 allows the caller to clone its current token and specify new credentials for outbound connections. The new logon session has the same local identify, but uses different credentials for other network connections."
* EID 10 GrantedAccess / Permissions 0x1010,0x1410 & 0x1038. 0x1038 is almost unique in an environment and 0x1410 is from old versions of Mimikatz.
  * 0x1000: PROCESS\_QUERY\_LIMITED\_INFORMATION
  * 0x0400: PROCESS\_QUERY\_INFORMATION
  * 0x0010: PROCESS\_VM\_READ
  * 0x0020: PROCESS\_VM\_WRITE (Required to write to memory in a process using WriteProcessMemory)
  * 0x0008: PROCESS\_VM\_OPERATION (Required to perform an operation on the address space of a process)
 * EID 4648: SecurityID different from Account Name is a sign of a user impersonating (using compromised credentials) another account.
 * EID 4768. Look for RC4 (0x17). Encryption Downgrades might be anomalies when you are not using it in your environment. Why all of the sudden one computer in HR is requesting TGTs with RC4?.

 
## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [X] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
