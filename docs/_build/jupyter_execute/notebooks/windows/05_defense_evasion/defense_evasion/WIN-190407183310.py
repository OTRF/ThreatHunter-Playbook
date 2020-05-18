# Enable Remote Desktop Conections Registry

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-190407183310 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2019/04/07 |
| platform      | Windows |
| playbook link |  |
        

## Technical Description
Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system.
Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials.
There are several settings that must be configured to enable Remote Desktop connections.
First, you must enable Remote Desktop connections by using the fDenyTSConnections setting.
Setting fDenyTSConnections=False in the Microsoft-Windows-TerminalServices-LocalSessionManager component (HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server) specifies whether Remote Desktop connections are enabled.

An adversary can also specify how users are authenticated.
Setting UserAuthentication=0 in the Microsoft-Windows-TerminalServices-RDP-WinStationExtensions component (HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp) helps make sure that users can connect remotely from computers that don't run Remote Desktop by using network-level authentication.
This is the equivalent of Allow connections from computers running any version of Remote Desktop (less secure) security setting.

## Hypothesis
Adversaries might be modifying registry key values to enable remote desktop connections in my environment

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/hunters-forge/mordor/master/datasets/small/windows/defense_evasion/empire_enable_rdp.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational']          | Look for any process updating fDenyTSConnections or UserAuthentication registry key values            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, Image, TargetObject
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 13
    AND (TargetObject LIKE "%fDenyTSConnections"
        OR TargetObject LIKE "%UserAuthentication")
    AND Details = "DWORD (0x00000000)"
    '''
)
df.show(10,False)

## Detection Blindspots


## Hunter Notes
* if the activity defined above happens frequently in your environment, you cshould Stack the processeses modifying the registry key values.

## Hunt Output

| Category | Type | Name     |
| :--------| :----| :--------|
| signature | SIGMA | [sysmon_rdp_registry_modification](https://github.com/hunters-forge/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_rdp_registry_modification.yml) |

## References
* https://attack.mitre.org/techniques/T1076/
* https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/management/enable_rdp.py
* https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-localsessionmanager-fdenytsconnections
* https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/enable-remote-desktop-by-using-an-answer-file