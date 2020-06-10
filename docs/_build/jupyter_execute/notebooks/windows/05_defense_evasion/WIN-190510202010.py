# WDigest Downgrade

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-190510202010 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2019/05/10 |
| platform      | Windows |
| playbook link |  |
        

## Technical Description
Windows 8.1 introduced a registry setting that allows for disabling the storage of the user’s logon credential in clear text for the WDigest provider.
This setting can be modified in the property UseLogonCredential for the registry key HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest.
If this key does not exists, you can create it and set it to 1 to enable clear text passwords.

## Hypothesis
Adversaries might have updated the property value UseLogonCredential of HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to 1 in order to be able to extract clear text passwords from memory contents of lsass.

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/hunters-forge/mordor/master/datasets/small/windows/defense_evasion/empire_wdigest_downgrade.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational']          | Look for any process updating UseLogonCredential registry key value            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, Image, TargetObject
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 13
    AND TargetObject LIKE "%UseLogonCredential"
    AND Details = 1
    '''
)
df.show(10,False)

## Detection Blindspots


## Hunter Notes


## Hunt Output

| Category | Type | Name     |
| :--------| :----| :--------|
| signature | SIGMA | [sysmon_wdigest_registry_modification](https://github.com/hunters-forge/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_wdigest_registry_modification.yml) |

## References
* https://github.com/samratashok/nishang/blob/master/Gather/Invoke-MimikatzWDigestDowngrade.ps1
* https://blog.stealthbits.com/wdigest-clear-text-passwords-stealing-more-than-a-hash/