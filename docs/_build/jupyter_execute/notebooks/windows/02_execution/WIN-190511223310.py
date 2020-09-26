# PowerShell Remote Session

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2019/05/11 |
| modification date | 2020/09/20 |
| playbook related  | ['WIN-190410151110'] |

## Hypothesis
Adversaries might be leveraging remote powershell sessions to execute code on remote systems throughout my environment

## Technical Context
None

## Offensive Tradecraft
Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.
In addition, it can be used to execute code remotely via Windows Remote Management (WinRM) services.
Therefore, it is important to understand the basic artifacts left when PowerShell is used to execute code remotely via a remote powershell session.

## Mordor Test Data


|           |           |
|:----------|:----------|
| metadata  | https://mordordatasets.com/notebooks/small/windows/02_execution/SDWIN-190518211456.html        |
| link      | [https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/lateral_movement/host/empire_psremoting_stager.zip](https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/lateral_movement/host/empire_psremoting_stager.zip)  |

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor Dataset

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/lateral_movement/host/empire_psremoting_stager.zip"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I
Process wsmprovhost hosts the active remote session on the target. Therefore, it is important to monitor for any the initialization of the PowerShell host wsmprovhost


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Powershell | Windows PowerShell | Application host started | 400 |
| Powershell | Microsoft-Windows-PowerShell/Operational | User started Application host | 4103 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Channel
FROM mordorTable
WHERE (Channel = "Microsoft-Windows-PowerShell/Operational" OR Channel = "Windows PowerShell")
    AND (EventID = 400 OR EventID = 4103)
    AND Message LIKE "%Host Application%wsmprovhost%"
'''
)
df.show(10,False)

### Analytic II
Monitor for any incoming network connection where the destination port is either 5985 or 5986. That will be hosted most likely by the System process. Layer ID:44


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Security-Auditing | Process connected to Port | 5156 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Application, SourceAddress, DestAddress, LayerName, LayerRTID
FROM mordorTable
WHERE LOWER(Channel) = "security"
    AND EventID = 5156
    AND (DestPort = 5985 OR DestPort = 5986)
    AND LayerRTID = 44
'''
)
df.show(10,False)

### Analytic III
Process wsmprovhost hosts the active remote session on the target. Therefore, from a process creation perspective, it is to document any instances of wsmprovhost being spawned and spawning other processes


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Security-Auditing | Process created Process | 4688 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, ParentProcessName, NewProcessName
FROM mordorTable
WHERE LOWER(Channel) = "security"
    AND EventID = 4688
    AND (ParentProcessName LIKE "%wsmprovhost.exe" OR NewProcessName LIKE "%wsmprovhost.exe")
'''
)
df.show(10,False)

### Analytic IV
Process wsmprovhost hosts the active remote session on the target. Therefore, from a process creation perspective, it is to document any instances of wsmprovhost being spawned and spawning other processes


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process created Process | 1 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, ParentImage, Image
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND (ParentImage LIKE "%wsmprovhost.exe" OR Image LIKE "%wsmprovhost.exe")
'''
)
df.show(10,False)

### Analytic V
Monitor for outbound network connection where the destination port is either 5985 or 5986 and the use is not NT AUTHORITY\NETWORK SERVICE


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | User connected to Port | 3 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, User, Initiated, Image, SourceIp, DestinationIp
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 3
    AND (DestinationPort = 5985 OR DestinationPort = 5986)
    AND NOT User = "NT AUTHORITY\\\\NETWORK SERVICE"
'''
)
df.show(10,False)

## Known Bypasses


| Idea | Playbook |
|:-----|:---------|

## False Positives
None

## Hunter Notes
* Explore the data produced in your lab environment with the analytics above and document what normal looks like from a PowerShell perspective. Then, take your findings and explore your production environment.
* If powershell activity locally or remotely via winrm happens all the time in your environment, I suggest to categorize the data you collect by business unit or department to document profiles.
* Layer 44 translatest to layer filter FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 / FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6. This filtering layer allows for authorizing accept requests for incoming TCP connections, as well as authorizing incoming non-TCP traffic based on the first packet received. Looking for destination ports related to remote PowerShell Sessions and Layer 44 is very helpful.

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | [https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/powershell_remote_powershell_session.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/powershell_remote_powershell_session.yml) |
| Sigma Rule | [https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_remote_powershell_session_network.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_remote_powershell_session_network.yml) |
| Sigma Rule | [https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_remote_powershell_session_process.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_remote_powershell_session_process.yml) |
| Sigma Rule | [https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_remote_powershell_session.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_remote_powershell_session.yml) |

## References
* https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-6#windows-powershell-remoting
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements?view=powershell-6
* https://docs.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-