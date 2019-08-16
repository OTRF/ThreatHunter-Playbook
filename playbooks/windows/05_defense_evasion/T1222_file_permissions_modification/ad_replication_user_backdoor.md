# Active Directory Replication User Backdoor

## Playbook Tags

**ID:** WINDEFE1901011511

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:** WINCRED1808152105

## ATT&CK Tags

**Tactic:** Defense Evasion

**Technique:** File Permissions Modification (T1222)

## Applies To

## Technical Description

Active Directory replication is the process by which the changes that originate on one domain controller are automatically transferred to other domain controllers that store the same data.

Active Directory data takes the form of objects that have properties, or attributes. Each object is an instance of an object class, and object classes and their respective attributes are defined in the Active Directory schema. The values of the attributes define the object, and a change to a value of an attribute must be transferred from the domain controller on which it occurs to every other domain controller that stores a replica of that object.

An adversary with enough permissions (domain admin) can add an ACL to the Root Domain for any user, despite being in no privileged groups, having no malicious sidHistory, and not having local admin rights on the domain controller. This is done to bypass detection rules looking for Domain Admins or the DC machine accounts performing active directory replication requests against a domain controller.

The following access rights / permissions are needed for the replication request according to the domain functional level:

| Control access right symbol | Identifying GUID used in ACE |
|-----------------------------|------------------------------|
| DS-Replication-Get-Changes | 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 |
| DS-Replication-Get-Changes-All | 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 |
| DS-Replication-Get-Changes-In-Filtered-Set | 89e95b76-444d-4c62-991a-0facbeda640c |

### Additional Reading

* [Active Directory Replication](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/library/active_directory_replication.md)

## Permission Required

Domain Admin

## Hypothesis

Adversaries might modifying the security descriptor of the root domain to grant active directory replication rights to any user, despite being in no privileged groups, having no malicious sidHistory, and not having local admin rights on the domain controller.

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_dcsync_acl](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/defense_evasion/file_permissions_modifications_T1222/ad_object_modification/empire_dcsync_acl.md)  | A mordor dataset to simulate an adversary modifying the security descriptor of the root domain to grant active directory replication rights to regular users |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [4662](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4662.md) | An operation was performed on an object | Microsoft-Windows-Security-Auditing | DS Access | Directory Service Access | Windows Event Logs |
| [5136](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136) | A directory service object was modified | Microsoft-Windows-Security-Auditing | DS Access | Directory Service Changes | Windows Event Logs |

## Data Analytics

| Analytic Type | Source | Analytic Logic |
|--------|---------|---------|
| Rule | Security | SELECT `@timestamp`, computer_name, SubjectUserName, ObjectName, OperationType FROM mordor_file WHERE channel = "Security" AND event_id = 4662 AND ObjectServer = "DS" AND AccessMask = "0x40000" AND ObjectType LIKE "%19195a5b_6da0_11d0_afd3_00c04fd930c9%" |
| Rule | Security | SELECT `@timestamp`, computer_name, SubjectUserName, ObjectDN, AttributeLDAPDisplayName FROM mordor_file WHERE channel = "Security" AND event_id = 5136 AND lower(AttributeLDAPDisplayName) = "ntsecuritydescriptor" AND (AttributeValue LIKE "%1131f6aa_9c07_11d1_f79f_00c04fc2dcd2%" OR AttributeValue LIKE "%1131f6ad_9c07_11d1_f79f_00c04fc2dcd2%" OR AttributeValue LIKE "%89e95b76_444d_4c62_991a_0facbeda640c%") |

## Detection Blind Spots

## Hunter Notes

* Looking for WRITE_DAC (0X40000) access by a Domain Admin on a Domain object and matching the guid of the `object_name` field to the root domain one is very interesting. You can add more context related to your environment to reduce the amount of events returnned.
* Right after the AD object is accessed with WRITE_DAC rights, the security descriptor of the ad object (root domain object) is modified to grant ad replication rights to the user creating a backdoor in the domain for potential DCSync actions.

## Hunt Output

| Category | Output Type | Name |
|--------|--------|---------|
| Signature | Sigma Rule | [win_ad_object_writedac_access.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_ad_object_writedac_access.yml) |
| Signature | Sigma Rule | [win_ad_replication_user_backdoor.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_ad_replication_user_backdoor.yml) |

## References

* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
* https://docs.microsoft.com/en-us/windows/desktop/adschema/c-domain
* https://docs.microsoft.com/en-us/windows/desktop/adschema/c-domaindns
* http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc782376(v=ws.10)
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47