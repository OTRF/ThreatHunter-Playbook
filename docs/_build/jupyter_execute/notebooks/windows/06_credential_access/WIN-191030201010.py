# Remote Interactive Task Manager LSASS Dump

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-191030201010 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2019/10/30 |
| platform      | Windows |
| playbook link | WIN-1904101010 |
        

## Technical Description
The Windows Task Manager may be used to dump the memory space of lsass.exe to disk for processing with a credential access tool such as Mimikatz.
This is performed by launching Task Manager as a privileged user, selecting lsass.exe, and clicking “Create dump file”.
This saves a dump file to disk with a deterministic name that includes the name of the process being dumped.

## Hypothesis
Adversaries might be RDPing to computers in my environment and interactively dumping the memory contents of LSASS with task manager.

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/credential_access/remoteinteractive_taskmngr_lsass_dump.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-Sysmon/Operational']          | Look for taskmgr creating files which name contains the string lsass and with extension .dmp.            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, Image, TargetFilename, ProcessGuid
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 11
    AND Image LIKE "%taskmgr.exe"
    AND lower(TargetFilename) RLIKE ".*lsass.*\.dmp"
    '''
)
df.show(10,False)

### Analytic II


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-Sysmon/Operational']          | Look for task manager access lsass and with functions from dbgcore.dll or dbghelp.dll libraries            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, SourceImage, TargetImage, GrantedAccess
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 10
    AND lower(SourceImage) LIKE "%taskmgr.exe"
    AND lower(TargetImage) LIKE "%lsass.exe"
    AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
    '''
)
df.show(10,False)

### Analytic III


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-Sysmon/Operational']          | Look for any process accessing lsass and with functions from dbgcore.dll or dbghelp.dll libraries            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, SourceImage, TargetImage, GrantedAccess
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 10
    AND lower(TargetImage) LIKE "%lsass.exe"
    AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
    '''
)
df.show(10,False)

### Analytic IV


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational']          | Look for combinations of process access and process creation to get more context around potential lsass dump form task manager or other binaries            |
            

df = spark.sql(
    '''
SELECT o.`@timestamp`, o.computer_name, o.Image, o.LogonId, o.ProcessGuid, a.SourceProcessGUID, o.CommandLine
FROM mordorTable o
INNER JOIN (
    SELECT computer_name,SourceProcessGUID
    FROM mordorTable
    WHERE channel = "Microsoft-Windows-Sysmon/Operational"
        AND event_id = 10
        AND lower(TargetImage) LIKE "%lsass.exe"
        AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
    ) a
ON o.ProcessGuid = a.SourceProcessGUID
WHERE o.channel = "Microsoft-Windows-Sysmon/Operational"
    AND o.event_id = 1
    '''
)
df.show(10,False)

### Analytic V


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational', 'Security']          | Look for binaries accessing lsass that are running under the same logon context of a user over an RDP session            |
            

df = spark.sql(
    '''
SELECT o.`@timestamp`, o.computer_name, o.SessionName, o.AccountName, o.ClientName, o.ClientAddress, a.Image, a.CommandLine
FROM mordorTable o
INNER JOIN (
    SELECT LogonId, Image, CommandLine
    FROM (
        SELECT o.Image, o.LogonId, o.CommandLine
        FROM mordorTable o
        INNER JOIN (
            SELECT computer_name,SourceProcessGUID
            FROM mordorTable
            WHERE channel = "Microsoft-Windows-Sysmon/Operational"
                AND event_id = 10
                AND lower(TargetImage) LIKE "%lsass.exe"
                AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
            ) a
        ON o.ProcessGuid = a.SourceProcessGUID
        WHERE o.channel = "Microsoft-Windows-Sysmon/Operational"
            AND o.event_id = 1
        )
    ) a
ON o.LogonID = a.LogonId
WHERE lower(o.channel) = "security"
    AND o.event_id = 4778
    '''
)
df.show(10,False)

## Detection Blindspots


## Hunter Notes
* Add context to your queries by joining RDP remote interactive authentication events by the logon ID.

## Hunt Output


## References
* https://car.mitre.org/analytics/CAR-2019-08-001/