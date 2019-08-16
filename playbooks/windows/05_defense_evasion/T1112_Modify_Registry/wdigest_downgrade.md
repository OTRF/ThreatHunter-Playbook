# WDigest Downgrade

## Playbook Tags

**ID:** WINDEFN1905102020

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:** 

## ATT&CK Tags

**Tactic:** Defense Evasion

**Technique:** Modify Registry (T1112)

## Applies To

## Technical Description

Windows 8.1 introduced a registry setting that allows for disabling the storage of the user’s logon credential in clear text for the WDigest provider. This setting can be modified in the property `UseLogonCredential` for the registry key HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest. If this key does not exists, you can create it and set it to 1 to enable clear text passwords.

## Permission Required

Administrator

## Hypothesis

Adversaries might have updated the property value UseLogonCredential of HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to 1 in order to be able to extract clear text passwords from memory contents of lsass.

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_wdigest_downgrade](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/defense_evasion/modify_registry_T1112/empire_wdigest_downgrade.md) | A mordor dataset to simulate the modification of the property value of UseLogonCredential from HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [13](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-13.md) | RegistryEvent ValueSet| Microsoft-Windows-Sysmon |  |  | Windows Registry |

## Data Analytics

| Analytic Type | Source | Analytic Logic |
|--------|---------|---------|
| Rule | Sysmon | SELECT `@timestamp`, computer_name, Image, TargetObject FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 13 AND TargetObject LIKE "%UseLogonCredential" AND Details = 1 |

## Detection Blind Spots

## Hunter Notes

## Hunt Output

| Category | Output Type | Name |
|--------|--------|---------|
|Signature | Sigma Rule | [sysmon_wdigest_registry_modification.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_wdigest_registry_modification.yml) |

## References

* https://github.com/samratashok/nishang/blob/master/Gather/Invoke-MimikatzWDigestDowngrade.ps1
* https://blog.stealthbits.com/wdigest-clear-text-passwords-stealing-more-than-a-hash/