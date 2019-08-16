# Enable Remote Desktop Conections Registry

## Playbook Tags

**ID:** WINDEFE1904071833

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:** 

## ATT&CK Tags

**Tactic:** Defense Evasion

**Technique:** Modify Registry (T1112)

## Applies To

## Technical Description

Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. There are several settings that must be configured to enable Remote Desktop connections. First, you must enable Remote Desktop connections by using the `fDenyTSConnections` setting. Setting `fDenyTSConnections=False` in the `Microsoft-Windows-TerminalServices-LocalSessionManager` component (HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server) specifies whether Remote Desktop connections are enabled.

An adversary can also specify how users are authenticated. Setting `UserAuthentication=0` in the `Microsoft-Windows-TerminalServices-RDP-WinStationExtensions` component (HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp) helps make sure that users can connect remotely from computers that don't run Remote Desktop by using network-level authentication. This is the equivalent of `Allow connections from computers running any version of Remote Desktop (less secure)` security setting.

## Permission Required

Administrator

## Hypothesis

Adversaries might be enabling remote desktop connections by modifying registry key values of the Microsoft-Windows-TerminalServices services in my environment.

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_enable_rdp](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/defense_evasion/modify_registry_T1112/empire_enable_rdp.md) | A mordor dataset to simulate the modification of registry key properties to enable RDP connections |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [13](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-13.md) | RegistryEvent ValueSet| Microsoft-Windows-Sysmon |  |  | Windows Registry |

## Data Analytics

| Analytic Type | Source | Analytic Logic |
|--------|---------|---------|
| Rule | Sysmon | SELECT `@timestamp`, computer_name, Image, TargetObject FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 13 AND (TargetObject LIKE "%fDenyTSConnections" OR TargetObject LIKE "%UserAuthentication") AND Details = "DWORD (0x00000000)" |

## Detection Blind Spots

## Hunter Notes

* If the activity defined above happens frequently in your environment, you cshould Stack the processeses modifying the registry key values.

## Hunt Output

| Category | Output Type | Name |
|--------|--------|---------|
| Signature | Sigma Rule | [sysmon_rdp_registry_modification.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_rdp_registry_modification.yml) |

## References

* https://attack.mitre.org/techniques/T1076/
* https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/management/enable_rdp.py
* https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-localsessionmanager-fdenytsconnections
* https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/enable-remote-desktop-by-using-an-answer-file