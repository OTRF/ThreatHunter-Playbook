# Basic PowerShell Execution

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-190410151110 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2019/04/10 |
| platform      | Windows |
| playbook link |  |
        

## Technical Description
Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.
Therefore, it is important to understand the basic artifacts left when PowerShell is used in your environment.

## Hypothesis
Adversaries might be leveraging PowerShell to execute code within my environment

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/execution/empire_launcher_vbs.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-PowerShell/Operational', 'PowerShell']          | Within the classic PowerShell log, event ID 400 indicates when a new PowerShell host process has started. You can filter on powershell.exe as a host application if you want to or leave it without a filter to captuer every single PowerShell host            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, channel
FROM mordorTable
WHERE (channel = "Microsoft-Windows-PowerShell/Operational" OR channel = "Windows PowerShell")
    AND (event_id = 400 OR event_id = 4103)
    '''
)
df.show(10,False)

### Analytic II


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| High       | ['Security']          | Looking for non-interactive powershell session might be a sign of PowerShell being executed by another application in the background            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, NewProcessName, ParentProcessName
FROM mordorTable
WHERE channel = "Security"
    AND event_id = 4688
    AND NewProcessName LIKE "%powershell.exe"
    AND NOT ParentProcessName LIKE "%explorer.exe"
    '''
)
df.show(10,False)

### Analytic III


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| High       | ['Microsoft-Windows-Sysmon/Operational']          | Looking for non-interactive powershell session might be a sign of PowerShell being executed by another application in the background            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, Image, ParentImage
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 1
    AND Image LIKE "%powershell.exe"
    AND NOT ParentImage LIKE "%explorer.exe"
    '''
)
df.show(10,False)

### Analytic IV


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-Sysmon/Operational']          | Monitor for processes loading PowerShell DLL *system.management.automation*            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, Image, ImageLoaded
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 7
    AND (lower(Description) = "system.management.automation" OR lower(ImageLoaded) LIKE "%system.management.automation%")
    '''
)
df.show(10,False)

### Analytic V


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-Sysmon/Operational']          | Monitoring for PSHost* pipes is another interesting way to find PowerShell execution            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, Image, PipeName
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 17
    AND lower(PipeName) LIKE "\\\\pshost%"
    '''
)
df.show(10,False)

### Analytic VI


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-Sysmon/Operational']          | The “PowerShell Named Pipe IPC” event will indicate the name of the PowerShell AppDomain that started. Sign of PowerShell execution            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, message
FROM mordorTable
WHERE channel = "Microsoft-Windows-PowerShell/Operational"
    AND event_id = 53504
    '''
)
df.show(10,False)

## Detection Blindspots


## Hunter Notes
* Explore the data produced in your environment with the analytics above and document what normal looks like from a PowerShell perspective.
* If execution of PowerShell happens all the time in your environment, I suggest to categorize the data you collect by business unit to build profiles and be able to filter out potential noise.
* You can also stack the values of the command line arguments being used. You can hash the command line arguments too and stack the values.

## Hunt Output

| Category | Type | Name     |
| :--------| :----| :--------|
| signature | SIGMA | [sysmon_powershell_execution_moduleload](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_powershell_execution_moduleload.yml) |
| signature | SIGMA | [sysmon_powershell_execution_pipe](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_powershell_execution_pipe.yml) |
| signature | SIGMA | [sysmon_non_interactive_powershell_execution](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_non_interactive_powershell_execution.yml) |
| signature | SIGMA | [win_non_interactive_powershell](https://github.com/OTRF/ThreatHunter-Playbook/tree/master/signatures/sigma/win_non_interactive_powershell.yml) |

## References
* https://github.com/darkoperator/Presentations/blob/master/PSConfEU%202019%20Tracking%20PowerShell%20Usage.pdf
* https://posts.specterops.io/abusing-powershell-desired-state-configuration-for-lateral-movement-ca42ddbe6f06