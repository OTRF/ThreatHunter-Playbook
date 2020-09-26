# Basic PowerShell Execution

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2019/04/10 |
| modification date | 2020/09/20 |
| playbook related  | [] |

## Hypothesis
Adversaries might be leveraging PowerShell to execute code within my environment

## Technical Context
None

## Offensive Tradecraft
Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.
Therefore, it is important to understand the basic artifacts left when PowerShell is used in your environment.

## Mordor Test Data


|           |           |
|:----------|:----------|
| metadata  | https://mordordatasets.com/notebooks/small/windows/02_execution/SDWIN-190518182022.html        |
| link      | [https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/execution/host/empire_launcher_vbs.zip](https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/execution/host/empire_launcher_vbs.zip)  |

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor Dataset

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/execution/host/empire_launcher_vbs.zip"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I
Within the classic PowerShell log, event ID 400 indicates when a new PowerShell host process has started. You can filter on powershell.exe as a host application if you want to or leave it without a filter to captuer every single PowerShell host


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
'''
)
df.show(10,False)

### Analytic II
Looking for non-interactive powershell session might be a sign of PowerShell being executed by another application in the background


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Security-Auditing | Process created Process | 4688 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, NewProcessName, ParentProcessName
FROM mordorTable
WHERE LOWER(Channel) = "security"
    AND EventID = 4688
    AND NewProcessName LIKE "%powershell.exe"
    AND NOT ParentProcessName LIKE "%explorer.exe"
'''
)
df.show(10,False)

### Analytic III
Looking for non-interactive powershell session might be a sign of PowerShell being executed by another application in the background


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process created Process | 1 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Image, ParentImage
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND Image LIKE "%powershell.exe"
    AND NOT ParentImage LIKE "%explorer.exe"
'''
)
df.show(10,False)

### Analytic IV
Monitor for processes loading PowerShell DLL *system.management.automation*


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Module | Microsoft-Windows-Sysmon/Operational | Process loaded Dll | 7 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Image, ImageLoaded
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 7
    AND (lower(Description) = "system.management.automation" OR lower(ImageLoaded) LIKE "%system.management.automation%")
'''
)
df.show(10,False)

### Analytic V
Monitoring for PSHost* pipes is another interesting way to find PowerShell execution


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Named Pipe | Microsoft-Windows-Sysmon/Operational | Process created Pipe | 17 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Image, PipeName
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 17
    AND lower(PipeName) LIKE "\\\\pshost%"
'''
)
df.show(10,False)

### Analytic VI
The “PowerShell Named Pipe IPC” event will indicate the name of the PowerShell AppDomain that started. Sign of PowerShell execution


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Powershell | Microsoft-Windows-PowerShell/Operational | Application domain started | 53504 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Message
FROM mordorTable
WHERE Channel = "Microsoft-Windows-PowerShell/Operational"
    AND EventID = 53504
'''
)
df.show(10,False)

## Known Bypasses


| Idea | Playbook |
|:-----|:---------|

## False Positives
None

## Hunter Notes
* Explore the data produced in your environment with the analytics above and document what normal looks like from a PowerShell perspective.
* If execution of PowerShell happens all the time in your environment, I suggest to categorize the data you collect by business unit to build profiles and be able to filter out potential noise.
* You can also stack the values of the command line arguments being used. You can hash the command line arguments too and stack the values.

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_powershell_execution_moduleload.yml](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_powershell_execution_moduleload.yml) |
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_powershell_execution_pipe.yml](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_powershell_execution_pipe.yml) |
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_non_interactive_powershell_execution.yml](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_non_interactive_powershell_execution.yml) |
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/win_non_interactive_powershell.yml](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/win_non_interactive_powershell.yml) |

## References
* https://github.com/darkoperator/Presentations/blob/master/PSConfEU%202019%20Tracking%20PowerShell%20Usage.pdf
* https://posts.specterops.io/abusing-powershell-desired-state-configuration-for-lateral-movement-ca42ddbe6f06