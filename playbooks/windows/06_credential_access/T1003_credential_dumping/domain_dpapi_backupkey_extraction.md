# Domain DPAPI Backup Key Extraction

## Playbook ID

WINCRED1906200246

## Author

Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

## Tactic Name(s)

Credential Access

## Technique ID(s)

T1003

## Applies To

## Playbook References

## Technical Description

Starting with Microsoft® Windows® 2000, the operating system began to provide a data protection application-programming interface (API). This Data Protection API (DPAPI) is a pair of function calls  `(CryptProtectData / CryptUnprotectData)` that provide operating system-level data protection services to user and system processes. DPAPI initially generates a strong key called a MasterKey, which is protected by the user's password. DPAPI uses a standard cryptographic process called Password-Based Key Derivation to generate a key from the password. This password-derived key is then used with Triple-DES to encrypt the MasterKey, which is finally stored in the user's profile directory.

When a computer is a member of a domain, DPAPI has a backup mechanism to allow unprotection of the data. When a MasterKey is generated, DPAPI talks to a Domain Controller. Domain Controllers have a domain-wide public/private key pair, associated solely with DPAPI. The local DPAPI client gets the Domain Controller public key from a Domain Controller by using a mutually authenticated and privacy protected RPC call. The client encrypts the MasterKey with the Domain Controller public key. It then stores this backup MasterKey along with the MasterKey protected by the user's password.

If an adversary obtains domain admin (or equivalent) privileges, the domain backup key can be stolen and used to decrypt any domain user master key. Tools such as Mimikatz with the method/module `lsadump::backupkeys` can be used to extract the domain backup key. It uses the LsaOpenPolicy/LsaRetrievePrivateData API calls (instead of MS-BKRP) to retrieve the value for the `G$BCKUPKEY_PREFERRED` and `G$BCKUPKEY_P` LSA secrets.

### Additional Reading:

* [Data Protection API (DPAPI)](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/library/data_protection_api.md)
* [LSA Policy Objects](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/library/lsa_policy_objects.md)

## Permission Required

Domain Admin

## Hypothesis

Adversaries might be extracting the domain backup key to be able to decrypt any domain user master key.

## False Positives

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_mimikatz_export_master_key](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/credential_access/credential_dumping_T1003/credentials_from_ad/empire_mimikatz_export_master_key.md) | A mordor dataset to simulate the extraction of the domain DPAPI backup key |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [4662](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4662.md) | An operation was performed on an object | Microsoft-Windows-Security-Auditing | DS Access | Directory Service Access | Windows Event Logs |
| [5145](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-5145.md) | A network share object was checked to see whether client can be granted desired access | Microsoft-Windows-Security-Auditing | Object Access | Detailed File Share | Windows Event Logs |
| [4692](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4692.md) | Backup of data protection master key was attempted | Microsoft-Windows-Security-Auditing | Detailed Tracking | DPAPI Activity | Windows Event Logs |
| [4624](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4624.md) | An account was successfully logged on | Microsoft-Windows-Security-Auditing | Audit Logon/Logoff | Audit Logon | Windows Event Logs |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Low | Security | SELECT `@timestamp`, computer_name, ObjectServer, ObjectType, ObjectName FROM mordor_file WHERE channel = "Security" AND event_id = 4662 AND AccessMask = "0x2" AND lower(ObjectName) LIKE "%bckupkey%" | Monitor for any SecretObject with the string BCKUPKEY in the ObjectName |
| Low | Security | SELECT o.`@timestamp`, o.computer_name, o.ObjectName, a.IpAddress FROM mordor_file o INNER JOIN \( SELECT computer_name,TargetUserName,TargetLogonId,IpAddress FROM mordor_file WHERE channel = "Security" AND LogonType = 3 AND IpAddress is not null AND NOT TargetUserName LIKE "%$" \) a ON o.SubjectLogonId = a.TargetLogonId WHERE channel = "Security" AND o.event_id = 4662 AND o.AccessMask = "0x2" AND lower(o.ObjectName) LIKE "%bckupkey%" AND o.computer_name = a.computer_name | We can get the user logon id of the user that accessed the \*bckupkey\* object and JOIN it with a successful logon event (4624) user logon id to find the source IP |
| Low | Security | SELECT `@timestamp`, computer_name, SubjectUserName, ShareName, RelativeTargetName, AccessMask, IpAddress FROM mordor_file WHERE channel = "Security" AND event_id = 5145 AND ShareName LIKE "%IPC%" AND RelativeTargetName = "protected_storage" | Monitoring for access to the protected_storage service is very interesting to document potential DPAPI activity over the network |
| Low | Security | SELECT `@timestamp`, computer_name, SubjectUserName, MasterKeyId, RecoveryKeyId FROM mordor_file WHERE channel = "Security" AND event_id = 4692| This event generates every time that a backup is attempted for the DPAPI Master Key. When a computer is a member of a domain, DPAPI has a backup mechanism to allow unprotection of the data. When a Master Key is generated, DPAPI communicates with a domain controller. |

## Detection Blind Spots

## Hunter Notes

* Backup key can be displayed as base64 blob or exported as a .pvk file on disk (Mimikatz-like)
* Windows security event 4692 (Backup of data protection master key was attempted) also generates every time a new DPAPI Master Key is generated

## Hunt Output

| Category | Type | Name |
|--------|---------|---------|
| Signature | Sigma Rule | [win_dpapi_domain_backupkey_extraction.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_dpapi_domain_backupkey_extraction.yml) |
| Signature | Sigma Rule | [win_protected_storage_service_access.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_protected_storage_service_access.yml) |
| Signature | Sigma Rule | [win_dpapi_domain_masterkey_backup_attempt.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_dpapi_domain_masterkey_backup_attempt.yml)

## Referennces

* https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/
* https://digital-forensics.sans.org/summit-archives/dfirprague14/Give_Me_the_Password_and_Ill_Rule_the_World_Francesco_Picasso.pdf
* https://docs.microsoft.com/en-us/windows/desktop/devnotes/pstore
* https://github.com/gentilkiwi/mimikatz/blob/641a3b29acd326d07269300d94dceafea041f760/mimikatz/modules/kuhl_m_lsadump.c#L1907
* https://github.com/GhostPack/SharpDPAPI/blob/6388040a92e59fc0d5a82b4ec31599aa6778fd3b/SharpDPAPI/lib/Backup.cs#L43
* https://github.com/gentilkiwi/mimikatz/blob/641a3b29acd326d07269300d94dceafea041f760/mimikatz/modules/kuhl_m_lsadump.c#L1906-L1926
* https://github.com/gentilkiwi/mimikatz/blob/641a3b29acd326d07269300d94dceafea041f760/mimikatz/modules/kuhl_m_lsadump.c#L1758
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/88c6bd18-6c40-4a82-ae19-fe7bfec5108b