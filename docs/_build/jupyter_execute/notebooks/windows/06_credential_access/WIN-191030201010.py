# Remote Interactive Task Manager LSASS Dump

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2019/10/30 |
| modification date | 2020/09/20 |
| playbook related  | ['WIN-1904101010'] |

## Hypothesis
Adversaries might be RDPing to computers in my environment and interactively dumping the memory contents of LSASS with task manager.

## Technical Context
None

## Offensive Tradecraft
The Windows Task Manager may be used to dump the memory space of lsass.exe to disk for processing with a credential access tool such as Mimikatz.
This is performed by launching Task Manager as a privileged user, selecting lsass.exe, and clicking “Create dump file”.
This saves a dump file to disk with a deterministic name that includes the name of the process being dumped.

## Mordor Test Data


|           |           |
|:----------|:----------|
| metadata  | https://mordordatasets.com/notebooks/small/windows/06_credential_access/SDWIN-191027055035.html        |
| link      | [https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip](https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip)  |

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor Dataset

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I
Look for taskmgr creating files which name contains the string lsass and with extension .dmp.


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| File | Microsoft-Windows-Sysmon/Operational | Process created File | 11 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Image, TargetFilename, ProcessGuid
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 11
    AND Image LIKE "%taskmgr.exe"
    AND lower(TargetFilename) RLIKE ".*lsass.*\.dmp"
'''
)
df.show(10,False)

### Analytic II
Look for task manager access lsass and with functions from dbgcore.dll or dbghelp.dll libraries


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process accessed Process | 10 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, SourceImage, TargetImage, GrantedAccess
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 10
    AND lower(SourceImage) LIKE "%taskmgr.exe"
    AND lower(TargetImage) LIKE "%lsass.exe"
    AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
'''
)
df.show(10,False)

### Analytic III
Look for any process accessing lsass and with functions from dbgcore.dll or dbghelp.dll libraries


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process accessed Process | 10 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, SourceImage, TargetImage, GrantedAccess
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 10
    AND lower(TargetImage) LIKE "%lsass.exe"
    AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
'''
)
df.show(10,False)

### Analytic IV
Look for combinations of process access and process creation to get more context around potential lsass dump form task manager or other binaries


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process accessed Process | 10 |
| Process | Microsoft-Windows-Sysmon/Operational | Process created Process | 1 |

df = spark.sql(
'''
SELECT o.`@timestamp`, o.Hostname, o.Image, o.LogonId, o.ProcessGuid, a.SourceProcessGUID, o.CommandLine
FROM mordorTable o
INNER JOIN (
    SELECT Hostname,SourceProcessGUID
    FROM mordorTable
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 10
        AND lower(TargetImage) LIKE "%lsass.exe"
        AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
    ) a
ON o.ProcessGuid = a.SourceProcessGUID
WHERE o.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND o.EventID = 1
'''
)
df.show(10,False)

### Analytic V
Look for binaries accessing lsass that are running under the same logon context of a user over an RDP session


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process accessed Process | 10 |
| Process | Microsoft-Windows-Sysmon/Operational | Process created Process | 1 |
| Authentication log | Microsoft-Windows-Security-Auditing | User authenticated Host | 4778 |

df = spark.sql(
'''
SELECT o.`@timestamp`, o.Hostname, o.SessionName, o.AccountName, o.ClientName, o.ClientAddress, a.Image, a.CommandLine
FROM mordorTable o
INNER JOIN (
    SELECT LogonId, Image, CommandLine
    FROM (
        SELECT o.Image, o.LogonId, o.CommandLine
        FROM mordorTable o
        INNER JOIN (
            SELECT Hostname,SourceProcessGUID
            FROM mordorTable
            WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND EventID = 10
                AND lower(TargetImage) LIKE "%lsass.exe"
                AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
            ) a
        ON o.ProcessGuid = a.SourceProcessGUID
        WHERE o.Channel = "Microsoft-Windows-Sysmon/Operational"
            AND o.EventID = 1
        )
    ) a
ON o.LogonID = a.LogonId
WHERE lower(o.Channel) = "security"
    AND o.EventID = 4778
'''
)
df.show(10,False)

## Known Bypasses


| Idea | Playbook |
|:-----|:---------|

## False Positives
None

## Hunter Notes
* Add context to your queries by joining RDP remote interactive authentication events by the logon ID.

## Hunt Output

| Type | Link |
| :----| :----|

## References
* https://car.mitre.org/analytics/CAR-2019-08-001/