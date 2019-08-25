# SysKey Registry Keys Access

## Playbook Tags

**ID:** WINDISC1906250246

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:**

## ATT&CK Tags

**Tactic:** Discovery

**Technique:** Query Registry (T1012)

## Applies To

## Technical Description

Every computer that runs Windows has its own local domain; that is, it has an account database for accounts that are specific to that computer. Conceptually,this is an account database like any other with accounts, groups, SIDs, and so on. These are referred to as local accounts, local groups, and so on. Because computers typically do not trust each other for account information, these identities stay local to the computer on which they were created.

Adversaries might use tools like Mimikatz with `lsadump::sam` commands or scripts such as [Invoke-PowerDump](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-PowerDump.ps1) to get the SysKey to decrypt Security Account Mannager (SAM) database entries (from registry or hive) and get NTLM, and sometimes LM hashes of local accounts passwords.

Adversaries can calculate the Syskey by using RegOpenKeyEx/RegQueryInfoKey API calls to query the appropriate class info and values from the HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\JD, HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Skew1, HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\GBG, and HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Data keys.

### Additional Reading:

* [Security Account Manager (SAM) Database](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/library/security_account_manager_database.md)
* [SysKey](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/library/syskey.md)

## Permission Required

System

## Hypothesis

Adversaries might be calculating the SysKey from registry key values to decrypt SAM entries

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_mimikatz_lsadump_sam](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/credential_access/credential_dumping_T1003/credentials_from_registry/empire_mimikatz_lsadump_sam.md) | A mordor dataset to simulate execution of Mimikatz module lsadump:sam to access specific registry keys to calculate the SysKey |
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_powerdump](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/credential_access/credential_dumping_T1003/credentials_from_registry/empire_powerdump.md) | A mordor dataset to simulate access to specific registry keys to calculate the SysKey |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [4663](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4663.md) | An attempt was made to access an object | Microsoft-Windows-Security-Auditing | Object Access | Kernel Object | Windows Event Logs |
| [4656](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4656.md) | A handle to an object was requested | Microsoft-Windows-Security-Auditing | Object Access | Kernel Object | Windows Event Logs |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Low | Security | SELECT `@timestamp`, ProcessName, ObjectName, AccessMask, event_id FROM mordor_file WHERE channel = "Security" AND (event_id = 4656 OR event_id = 4663) AND ObjectType = "Key" AND (lower(ObjectName) LIKE "%jd" OR lower(ObjectName) LIKE "%gbg" OR lower(ObjectName) LIKE "%data" OR lower(ObjectName) LIKE "%skew1") | Look for handle requests and access operations to specific registry keys used to calculate the SysKey. SACLs are needed for them |

## False Positives

## Detection Blind Spots

* Apparently the registry keys needed to calculate the SysKey are accessed by processes such as smss.exe, winlogon.exe and syskey.exe, but when the system boots. An adversary can migrate to those processes to blend in.

## Hunter Notes

* An audit rule needs to be added to the SACL of the following keys to monitor for ReadKey rights:
    * HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\JD
    * HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Skew1
    * HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\GBG
    * HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Data
* Defenders can correlate known processes accessing those registry keys with events that tell you when the system boots up.

## Hunt Output

| Category | Type | Name |
|--------|---------|---------|
| Signature | Sigma Rule | [win_syskey_registry_access.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_syskey_registry_access.yml) |

## Referennces

* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump
* https://adsecurity.org/?page_id=1821#LSADUMPSAM
* http://www.harmj0y.net/blog/activedirectory/remote-hash-extraction-on-demand-via-host-security-descriptor-modification/
* https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.registryrights?view=netframework-4.8
* https://docs.microsoft.com/en-us/windows/desktop/sysinfo/registry-key-security-and-access-rights