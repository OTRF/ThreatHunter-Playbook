# WDigest Downgrade

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2019/05/10 |
| modification date | 2020/09/20 |
| playbook related  | [] |

## Hypothesis
Adversaries might have updated the property value UseLogonCredential of HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to 1 in order to be able to extract clear text passwords from memory contents of lsass.

## Technical Context
Windows 8.1 introduced a registry setting that allows for disabling the storage of the user’s logon credential in clear text for the WDigest provider.

## Offensive Tradecraft
This setting can be modified in the property UseLogonCredential for the registry key HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest.
If this key does not exists, you can create it and set it to 1 to enable clear text passwords.

## Mordor Test Data


|           |           |
|:----------|:----------|
| metadata  | https://mordordatasets.com/notebooks/small/windows/05_defense_evasion/SDWIN-190518201922.html        |
| link      | [https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/defense_evasion/host/empire_wdigest_downgrade.tar.gz](https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/defense_evasion/host/empire_wdigest_downgrade.tar.gz)  |

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor Dataset

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/defense_evasion/host/empire_wdigest_downgrade.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I
Look for any process updating UseLogonCredential registry key value


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows registry | Microsoft-Windows-Sysmon/Operational | Process modified Windows registry key value | 13 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Image, TargetObject
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 13
    AND TargetObject LIKE "%UseLogonCredential"
    AND Details = 1
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
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_wdigest_registry_modification.yml](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_wdigest_registry_modification.yml) |

## References
* https://github.com/samratashok/nishang/blob/master/Gather/Invoke-MimikatzWDigestDowngrade.ps1
* https://blog.stealthbits.com/wdigest-clear-text-passwords-stealing-more-than-a-hash/