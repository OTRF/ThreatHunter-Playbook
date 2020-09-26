# SysKey Registry Keys Access

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2019/06/25 |
| modification date | 2020/09/20 |
| playbook related  | [] |

## Hypothesis
Adversaries might be calculating the SysKey from registry key values to decrypt SAM entries

## Technical Context
Every computer that runs Windows has its own local domain; that is, it has an account database for accounts that are specific to that computer.
Conceptually,this is an account database like any other with accounts, groups, SIDs, and so on. These are referred to as local accounts, local groups, and so on.
Because computers typically do not trust each other for account information, these identities stay local to the computer on which they were created.

## Offensive Tradecraft
Adversaries might use tools like Mimikatz with lsadump::sam commands or scripts such as Invoke-PowerDump to get the SysKey to decrypt Security Account Mannager (SAM) database entries (from registry or hive) and get NTLM, and sometimes LM hashes of local accounts passwords.
Adversaries can calculate the Syskey by using RegOpenKeyEx/RegQueryInfoKey API calls to query the appropriate class info and values from the HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\JD, HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Skew1, HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\GBG, and HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Data keys.

Additional reading
* https://github.com/OTRF/ThreatHunter-Playbook/tree/master/docs/library/security_account_manager_database.md
* https://github.com/OTRF/ThreatHunter-Playbook/tree/master/docs/library/library/syskey.md

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
Look for handle requests and access operations to specific registry keys used to calculate the SysKey. SACLs are needed for them


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows registry | Microsoft-Windows-Security-Auditing | Process accessed Windows registry key | 4663 |
| Windows registry | Microsoft-Windows-Security-Auditing | Process requested access Windows registry key | 4656 |

df = spark.sql(
'''
SELECT `@timestamp`, ProcessName, ObjectName, AccessMask, EventID
FROM mordorTable
WHERE LOWER(Channel) = "security"
    AND (EventID = 4656 OR EventID = 4663)
    AND ObjectType = "Key"
    AND (
        lower(ObjectName) LIKE "%jd"
        OR lower(ObjectName) LIKE "%gbg"
        OR lower(ObjectName) LIKE "%data"
        OR lower(ObjectName) LIKE "%skew1"
    )
'''
)
df.show(10,False)

## Known Bypasses


| Idea | Playbook |
|:-----|:---------|
| Apparently the registry keys needed to calculate the SysKey are accessed by processes such as smss.exe, winlogon.exe and syskey.exe, but when the system boots. An adversary can migrate to those processes to blend in. | [None](https://github.com/OTRF/ThreatHunter-Playbook/blob/master/playbooks/None.yaml) |

## False Positives
None

## Hunter Notes
* An audit rule needs to be added to the SACL of the following keys to monitor for ReadKey rights
  * HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\JD
  * HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Skew1
  * HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\GBG
  * HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Data
* Defenders can correlate known processes accessing those registry keys with events that tell you when the system boots up.
* Look for the same process accessing all those registry keys in a short period of time.

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | [https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_syskey_registry_access.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_syskey_registry_access.yml) |

## References
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump
* https://adsecurity.org/?page_id=1821#LSADUMPSAM
* http://www.harmj0y.net/blog/activedirectory/remote-hash-extraction-on-demand-via-host-security-descriptor-modification/
* https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.registryrights?view=netframework-4.8
* https://docs.microsoft.com/en-us/windows/desktop/sysinfo/registry-key-security-and-access-rights