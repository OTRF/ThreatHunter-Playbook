# Enable Remote Desktop Conections Registry

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2019/04/07 |
| modification date | 2020/09/20 |
| playbook related  | [] |

## Hypothesis
Adversaries might be modifying registry key values to enable remote desktop connections in my environment

## Technical Context
Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system.
Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).

## Offensive Tradecraft
Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials.
There are several settings that must be configured to enable Remote Desktop connections.
First, you must enable Remote Desktop connections by using the fDenyTSConnections setting.
Setting fDenyTSConnections=False in the Microsoft-Windows-TerminalServices-LocalSessionManager component (HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server) specifies whether Remote Desktop connections are enabled.

An adversary can also specify how users are authenticated.
Setting UserAuthentication=0 in the Microsoft-Windows-TerminalServices-RDP-WinStationExtensions component (HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp) helps make sure that users can connect remotely from computers that don't run Remote Desktop by using network-level authentication.
This is the equivalent of Allow connections from computers running any version of Remote Desktop (less secure) security setting.

## Mordor Test Data


|           |           |
|:----------|:----------|
| metadata  | https://mordordatasets.com/notebooks/small/windows/05_defense_evasion/SDWIN-190518203650.html        |
| link      | [https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/defense_evasion/host/empire_enable_rdp.tar.gz](https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/defense_evasion/host/empire_enable_rdp.tar.gz)  |

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor Dataset

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/defense_evasion/host/empire_enable_rdp.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I
Look for any process updating fDenyTSConnections or UserAuthentication registry key values


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows registry | Microsoft-Windows-Sysmon/Operational | Process modified Windows registry key value | 13 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Image, TargetObject
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 13
    AND (TargetObject LIKE "%fDenyTSConnections"
        OR TargetObject LIKE "%UserAuthentication")
    AND Details = "DWORD (0x00000000)"
'''
)
df.show(10,False)

## Known Bypasses


| Idea | Playbook |
|:-----|:---------|

## False Positives
None

## Hunter Notes
* if the activity defined above happens frequently in your environment, you cshould Stack the processeses modifying the registry key values.

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_rdp_registry_modification.yml](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_rdp_registry_modification.yml) |

## References
* https://attack.mitre.org/techniques/T1076/
* https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/management/enable_rdp.py
* https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-localsessionmanager-fdenytsconnections
* https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/enable-remote-desktop-by-using-an-answer-file