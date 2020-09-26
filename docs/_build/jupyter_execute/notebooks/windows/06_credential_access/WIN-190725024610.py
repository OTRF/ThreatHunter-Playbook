# SAM Registry Hive Handle Request

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2019/07/25 |
| modification date | 2020/09/20 |
| playbook related  | ['WIN-190625024610'] |

## Hypothesis
Adversaries might be getting a handle to the SAM database to extract credentials in my environment

## Technical Context
Every computer that runs Windows has its own local domain; that is, it has an account database for accounts that are specific to that computer.
Conceptually,this is an account database like any other with accounts, groups, SIDs, and so on.
These are referred to as local accounts, local groups, and so on.
Because computers typically do not trust each other for account information, these identities stay local to the computer on which they were created.

## Offensive Tradecraft
Adversaries might use tools like Mimikatz with lsadump::sam commands or scripts such as Invoke-PowerDump to get the SysKey to decrypt Security Account Mannager (SAM) database entries (from registry or hive) and get NTLM, and sometimes LM hashes of local accounts passwords.

In addition, adversaries can use the built-in Reg.exe utility to dump the SAM hive in order to crack it offline.

Additional reading
* https://github.com/OTRF/ThreatHunter-Playbook/tree/master/docs/library/security_account_manager_database.md
* https://github.com/OTRF/ThreatHunter-Playbook/tree/master/docs/library/syskey.md

## Mordor Test Data


|           |           |
|:----------|:----------|
| metadata  | https://mordordatasets.com/notebooks/small/windows/06_credential_access/SDWIN-190625103712.html        |
| link      | [https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/credential_access/host/empire_mimikatz_sam_access.zip](https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/credential_access/host/empire_mimikatz_sam_access.zip)  |

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor Dataset

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/credential_access/host/empire_mimikatz_sam_access.zip"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I
Monitor for any handle requested for the SAM registry hive


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows registry | Microsoft-Windows-Security-Auditing | Process requested access Windows registry key | 4656 |
| Windows registry | Microsoft-Windows-Security-Auditing | User requested access Windows registry key | 4656 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, SubjectUserName, ProcessName, ObjectName, AccessMask
FROM mordorTable
WHERE LOWER(Channel) = "security"
    AND EventID = 4656
    AND ObjectType = "Key"
    AND lower(ObjectName) LIKE "%sam"
'''
)
df.show(10,False)

## Known Bypasses


| Idea | Playbook |
|:-----|:---------|

## False Positives
None

## Hunter Notes
None

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | [https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_sam_registry_hive_handle_request.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_sam_registry_hive_handle_request.yml) |
| Sigma Rule | [https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_sam_registry_hive_dump_via_reg_utility.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_sam_registry_hive_dump_via_reg_utility.yml) |

## References
* http://www.harmj0y.net/blog/activedirectory/remote-hash-extraction-on-demand-via-host-security-descriptor-modification/
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump
* https://adsecurity.org/?page_id=1821#LSADUMPSAM