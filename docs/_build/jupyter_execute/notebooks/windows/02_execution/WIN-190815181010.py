# Alternate PowerShell Hosts

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2019/08/15 |
| modification date | 2020/09/20 |
| playbook related  | ['WIN-190410151110'] |

## Hypothesis
Adversaries might be leveraging alternate PowerShell Hosts to execute PowerShell evading traditional PowerShell detections that look for powershell.exe in my environment.

## Technical Context
None

## Offensive Tradecraft
Adversaries can abuse alternate signed PowerShell Hosts to evade application whitelisting solutions that block powershell.exe and naive logging based upon traditional PowerShell hosts.
Characteristics of a PowerShell host (Matt Graeber @mattifestation) >
* These binaries are almost always C#/.NET .exes/.dlls
* These binaries have System.Management.Automation.dll as a referenced assembly
* These may not always be “built in” binaries

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
Within the classic PowerShell log, event ID 400 indicates when a new PowerShell host process has started. Excluding PowerShell.exe is a good way to find alternate PowerShell hosts


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
    AND NOT Message LIKE "%Host Application%powershell%"
'''
)
df.show(10,False)

### Analytic II
Looking for processes loading a specific PowerShell DLL is a very effective way to document the use of PowerShell in your environment


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Module | Microsoft-Windows-Sysmon/Operational | Process loaded Dll | 7 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Image, Description
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 7
    AND (lower(Description) = "system.management.automation" OR lower(ImageLoaded) LIKE "%system.management.automation%")
    AND NOT Image LIKE "%powershell.exe"
'''
)
df.show(10,False)

### Analytic III
Monitoring for PSHost* pipes is another interesting way to find other alternate PowerShell hosts in your environment.


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Named pipe | Microsoft-Windows-Sysmon/Operational | Process created Pipe | 17 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Image, PipeName
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 17
    AND lower(PipeName) LIKE "\\\pshost%"
    AND NOT Image LIKE "%powershell.exe"
'''
)
df.show(10,False)

## Known Bypasses


| Idea | Playbook |
|:-----|:---------|

## False Positives
None

## Hunter Notes
* Explore the data produced in your lab environment with the analytics above and document what normal looks like from alternate powershell hosts. Then, take your findings and explore your production environment.
* You can also run the script below named PowerShellHostFinder.ps1 by Matt Graber and audit PS host binaries in your environment.

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/powershell_alternate_powershell_hosts.yml](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/powershell_alternate_powershell_hosts.yml) |
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_alternate_powershell_hosts_moduleload.yml](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_alternate_powershell_hosts_moduleload.yml) |
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_alternate_powershell_hosts_pipe.yml](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_alternate_powershell_hosts_pipe.yml) |

## References
* https://twitter.com/mattifestation/status/971840487882506240
* https://gist.githubusercontent.com/mattifestation/fcae777470f1bdeb9e4b32f93c245fd3/raw/abbe79c660829ab9aad58581baf681655f6ba305/PowerShellHostFinder.ps1