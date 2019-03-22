# DCSync From Non-Domain-Controller Accounts

## Playbook ID

EWR001

## Technique ID

T1003

## Hypothesis

Adversaries might attempt to pull the NTLM hash of a user via active directory replication apis from a non-domain-controller account with permissions to do so.

## Attack Knowledge

Active Directory replication is the process by which the changes that originate on one domain controller are automatically transferred to other domain controllers that store the same data.

Active Directory data takes the form of objects that have properties, or attributes. Each object is an instance of an object class, and object classes and their respective attributes are defined in the Active Directory schema. The values of the attributes define the object, and a change to a value of an attribute must be transferred from the domain controller on which it occurs to every other domain controller that stores a replica of that object.

An adversary can abuse this model and request information about a specific account via the replication request. This is done from an account with permissions to perform that request. Usually you will see the domain controller account (i.e dcaccount$) doing this which might be an anomaly to see other non-dc-accounts doing it.

The following access rights / permissions are needed for the replication request according to the domain functional level:

| Control access right symbol | Identifying GUID used in ACE |
|------------------------------|-----------------------------|
| DS-Replication-Get-Changes | 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 |
| DS-Replication-Get-Changes-All | 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 |
| DS-Replication-Get-Changes-In-Filtered-Set | 89e95b76-444d-4c62-991a-0facbeda640c |

More information about the control access rights can be found [here](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb)

Active directory replication is possible via the Directory Replication Service (DRS) Remote Protocol. If a DC wants to connect to a DC in a particular domain. The DC constructs the following SPN:

`<DRS interface GUID>/<DSA GUID>/<DNS domain name>`

where the DRS Interface GUID is the fixed DRS RPC interface GUID, which has the well-known value of "E3514235-4B06-11D1-AB04-00C04FC2DCD2". This is useful for when auditing RPC via its ETW provider `Microsoft-Windows-RPC`.

## Attack Emulation Dataset

| RT Platform  | Dataset | Author |
|---------|---------|---------|
| Empire | [empire_dcsync](https://github.com/Cyb3rWard0g/mordor/tree/master/small_datasets/windows/credential_access/credential_dumping_T1003/credentials_from_ad) | Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |

## Relevant Data Sources

| ATT&CK Data Source | Log Provider | Data Category | Data Sub-Category | Event ID |
|---------|---------|----------|----------|---------|--------|
|Windows Event Logs | Microsoft-Windows-Security-Auditing | Audit DS Access	| Audit Directory Service Access | [4662](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4662.md) |
| | Microsoft-Windows-RPC | | | |

## Data Model

| Data Object | Relationship | Data Object | Event ID |
|--------|---------|-------|--------|
|  user | accessed | ad object | 4662 |

## Data Analytics

| Analytic Type  | Analytic Logic | Analytic Platform |
|--------|---------|---------|---------|
| Rule |  event_id:4662 NOT user_name:*$ AND object_properties:("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR "*89e95b76-444d-4c62-991a-0facbeda640c*")| Kibana |

## Potential False Positives

* Adversary is using an account that is not a domain controller but authorized and currently performing active directory replication tasks as part of a daily operation.

## Hunter Notes

* 

## References

* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
* https://docs.microsoft.com/en-us/windows/desktop/adschema/c-domain
* https://docs.microsoft.com/en-us/windows/desktop/adschema/c-domaindns
* http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/
* http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc782376(v=ws.10)
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/41efc56e-0007-4e88-bafe-d7af61efd91f