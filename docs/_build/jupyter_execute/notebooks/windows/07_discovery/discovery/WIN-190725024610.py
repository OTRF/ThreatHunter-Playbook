# SAM Registry Hive Handle Request

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-190725024610 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2019/07/25 |
| platform      | Windows |
| playbook link | WIN-190625024610 |
        

## Technical Description
Every computer that runs Windows has its own local domain; that is, it has an account database for accounts that are specific to that computer.
Conceptually,this is an account database like any other with accounts, groups, SIDs, and so on.
These are referred to as local accounts, local groups, and so on.
Because computers typically do not trust each other for account information, these identities stay local to the computer on which they were created.
Adversaries might use tools like Mimikatz with lsadump::sam commands or scripts such as Invoke-PowerDump to get the SysKey to decrypt Security Account Mannager (SAM) database entries (from registry or hive) and get NTLM, and sometimes LM hashes of local accounts passwords.

In addition, adversaries can use the built-in Reg.exe utility to dump the SAM hive in order to crack it offline.

Additional reading
* https://github.com/hunters-forge/ThreatHunter-Playbook/tree/master/docs/content/library/security_account_manager_database.md
* https://github.com/hunters-forge/ThreatHunter-Playbook/tree/master/docs/content/library/syskey.md

## Hypothesis
Adversaries might be getting a handle to the SAM database to extract credentials in my environment

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/hunters-forge/mordor/master/datasets/small/windows/credential_access/empire_mimikatz_lsadump_sam.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Security']          | Monitor for any handle requested for the SAM registry hive            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, SubjectUserName, ProcessName, ObjectName, AccessMask
FROM mordorTable
WHERE channel = "Security"
    AND event_id = 4656
    AND ObjectType = "Key"
    AND lower(ObjectName) LIKE "%sam"
    '''
)
df.show(10,False)

## Detection Blindspots


## Hunter Notes


## Hunt Output

| Category | Type | Name     |
| :--------| :----| :--------|
| signature | SIGMA | [win_sam_registry_hive_handle_request](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_sam_registry_hive_handle_request.yml) |
| signature | SIGMA | [win_sam_registry_hive_dump_via_reg_utility](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_sam_registry_hive_dump_via_reg_utility.yml) |

## References
* http://www.harmj0y.net/blog/activedirectory/remote-hash-extraction-on-demand-via-host-security-descriptor-modification/
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump
* https://adsecurity.org/?page_id=1821#LSADUMPSAM