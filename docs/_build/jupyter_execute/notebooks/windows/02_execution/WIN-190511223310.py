# PowerShell Remote Session

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-190511223310 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2019/05/11 |
| platform      | Windows |
| playbook link | WIN-190410151110 |
        

## Technical Description
Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.
In addition, it can be used to execute code remotely via Windows Remote Management (WinRM) services.
Therefore, it is important to understand the basic artifacts left when PowerShell is used to execute code remotely via a remote powershell session.

## Hypothesis
Adversaries might be leveraging remote powershell sessions to execute code on remote systems throughout my environment

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/execution/empire_invoke_psremoting.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['PowerShell', 'Microsoft-Windows-PowerShell/Operational']          | Process wsmprovhost hosts the active remote session on the target. Therefore, it is important to monitor for any the initialization of the PowerShell host wsmprovhost            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, channel
FROM mordorTable
WHERE (channel = "Microsoft-Windows-PowerShell/Operational" OR channel = "Windows PowerShell")
    AND (event_id = 400 OR event_id = 4103)
    AND message LIKE "%Host Application%wsmprovhost%"
    '''
)
df.show(10,False)

### Analytic II


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Security']          | Monitor for any incoming network connection where the destination port is either 5985 or 5986. That will be hosted most likely by the System process. Layer ID:44            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, Application, SourceAddress, DestAddress, LayerName, LayerRTID
FROM mordorTable
WHERE channel = "Security"
    AND event_id = 5156
    AND (DestPort = 5985 OR DestPort = 5986)
    AND LayerRTID = 44
    '''
)
df.show(10,False)

### Analytic III


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Security']          | Process wsmprovhost hosts the active remote session on the target. Therefore, from a process creation perspective, it is to document any instances of wsmprovhost being spawned and spawning other processes            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, ParentProcessName, NewProcessName
FROM mordorTable
WHERE channel = "Security"
    AND event_id = 4688
    AND (ParentProcessName LIKE "%wsmprovhost.exe" OR NewProcessName LIKE "%wsmprovhost.exe")
    '''
)
df.show(10,False)

### Analytic IV


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational']          | Process wsmprovhost hosts the active remote session on the target. Therefore, from a process creation perspective, it is to document any instances of wsmprovhost being spawned and spawning other processes            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, ParentImage, Image
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 1
    AND (ParentImage LIKE "%wsmprovhost.exe" OR Image LIKE "%wsmprovhost.exe")
    '''
)
df.show(10,False)

### Analytic V


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational']          | Monitor for outbound network connection where the destination port is either 5985 or 5986 and the use is not NT AUTHORITY\NETWORK SERVICE            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, User, Initiated, Image, SourceIp, DestinationIp
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 3
    AND (DestinationPort = 5985 OR DestinationPort = 5986)
    AND NOT User = "NT AUTHORITY\\\\NETWORK SERVICE"
    '''
)
df.show(10,False)

## Detection Blindspots


## Hunter Notes
* Explore the data produced in your lab environment with the analytics above and document what normal looks like from a PowerShell perspective. Then, take your findings and explore your production environment.
* If powershell activity locally or remotely via winrm happens all the time in your environment, I suggest to categorize the data you collect by business unit or department to document profiles.
* Layer 44 translatest to layer filter FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 / FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6. This filtering layer allows for authorizing accept requests for incoming TCP connections, as well as authorizing incoming non-TCP traffic based on the first packet received. Looking for destination ports related to remote PowerShell Sessions and Layer 44 is very helpful.

## Hunt Output

| Category | Type | Name     |
| :--------| :----| :--------|
| signature | SIGMA | [powershell_remote_powershell_session](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/powershell_remote_powershell_session.yml) |
| signature | SIGMA | [sysmon_remote_powershell_session_network](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_remote_powershell_session_network.yml) |
| signature | SIGMA | [sysmon_remote_powershell_session_process](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_remote_powershell_session_process.yml) |
| signature | SIGMA | [win_remote_powershell_session](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_remote_powershell_session.yml) |

## References
* https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-6#windows-powershell-remoting
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements?view=powershell-6
* https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-