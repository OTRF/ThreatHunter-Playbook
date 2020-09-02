# Remote WMI ActiveScriptEventConsumers

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-200902020333 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2020/09/02 |
| platform      | Windows |
| playbook link |  |
        

## Technical Description
Threat actors can achieve remote code execution by using WMI event subscriptions. Normally, a permanent WMI event subscription is designed to persist and respond to certain events.
According to [Matt Graeber](https://twitter.com/mattifestation), if an attacker wanted to execute a single payload however, the respective event consumer would just need to delete its corresponding event filter, consumer, and filter to consumer binding.
The advantage of this technique is that the payload runs as SYSTEM, and it avoids having a payload be displayed in plaintext in the presence of command line auditing.

One of the components of an Event subscription is the event consumer. It is basically the main action that gets executed when a filter triggers (i.e. monitor for authentication events. if one occurs. trigger the consumer).

According to [MS Documentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/standard-consumer-classes), there are several WMI consumer classes available:

* ActiveScriptEventConsumer: Executes a predefined script in an arbitrary scripting language when an event is delivered to it. Example: [Running a Script Based on an Event](https://docs.microsoft.com/en-us/windows/win32/wmisdk/running-a-script-based-on-an-event)
* CommandLineEventConsumer: Launches an arbitrary process in the local system context when an event is delivered to it. Example: [Running a Program from the Command Line Based on an Event](https://docs.microsoft.com/en-us/windows/win32/wmisdk/running-a-program-from-the-command-line-based-on-an-event)
* LogFileEventConsumer: Writes customized strings to a text log file when events are delivered to it. Example: [Writing to a Log File Based on an Event](https://docs.microsoft.com/en-us/windows/win32/wmisdk/writing-to-a-log-file-based-on-an-event)
* NTEventLogEventConsumer: Logs a specific message to the Windows event log when an event is delivered to it. Example: [Logging to NT Event Log Based on an Event](https://docs.microsoft.com/en-us/windows/win32/wmisdk/logging-to-nt-event-log-based-on-an-event)
* ScriptingStandardConsumerSetting 	Provides registration data common to all instances of the ActiveScriptEventConsumer class.
* SMTPEventConsumer 	Sends an email message using SMTP each time an event is delivered to it. Example: [Sending Email Based on an Event](https://docs.microsoft.com/en-us/windows/win32/wmisdk/sending-e-mail-based-on-an-event)

The ActiveScriptEventConsumer class allows for the execution of scripting code from either JScript or VBScript engines. Finally, the WMI script host process is `%SystemRoot%\system32\wbem\scrcons.exe`.

## Hypothesis
Adversaries might be leveraging WMI ActiveScriptEventConsumers remotely to move laterally in my network.

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/lateral_movement/covenant_wmi_event_subscription.zip"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-Sysmon/Operational']          | Look for the creation of Event consumers of script type.            |
            

df = spark.sql(
    '''
SELECT EventID, EventType
FROM mordorTable
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
  AND EventID = 20
  AND LOWER(Message) Like '%type: script%'
    '''
)
df.show(10,False)

### Analytic II


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-WMI-Activity/Operational']          | Look for the creation of Event consumers of script type (i.e vbscript).            |
            

df = spark.sql(
    '''
SELECT EventID, SourceName
FROM mordorTable
WHERE Channel = 'Microsoft-Windows-WMI-Activity/Operational'
  AND EventID = 5861
  AND LOWER(Message) LIKE '%scriptingengine = "vbscript"%'
    '''
)
df.show(10,False)

### Analytic III


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-Sysmon/Operational']          | Look for any indicators that the WMI script host process %SystemRoot%\system32\wbem\scrcons.exe is created. This is created by svchost.exe.            |
            

df = spark.sql(
    '''
SELECT ParentImage, Image, CommandLine, ProcessId, ProcessGuid
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND Image LIKE '%scrcons%'
    '''
)
df.show(10,False)

### Analytic IV


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Security']          | Look for any indicators that the WMI script host process %SystemRoot%\system32\wbem\scrcons.exe is created. This is created by svchost.exe.            |
            

df = spark.sql(
    '''
SELECT ParentProcessName, NewProcessName, CommandLine, NewProcessId
FROM mordorTable
WHERE LOWER(Channel) = "security"
    AND EventID = 4688
    AND NewProcessName LIKE '%scrcons%'
    '''
)
df.show(10,False)

### Analytic V


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-Sysmon/Operational']          | Look for any indicators that the WMI script host process %SystemRoot%\system32\wbem\scrcons.exe is being used. You can do this by looking for a few modules being loaded by a process.            |
            

df = spark.sql(
    '''
SELECT Image, ImageLoaded, Description, ProcessGuid
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 7
    AND LOWER(ImageLoaded) IN (
        'c:\\\windows\\\system32\\\wbem\\\scrcons.exe',
        'c:\\\windows\\\system32\\\\vbscript.dll',
        'c:\\\windows\\\system32\\\wbem\\\wbemdisp.dll',
        'c:\\\windows\\\system32\\\wshom.ocx',
        'c:\\\windows\\\system32\\\scrrun.dll'
    )
    '''
)
df.show(10,False)

### Analytic VI


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational']          | Look for any indicators that the WMI script host process %SystemRoot%\system32\wbem\scrcons.exe is being used and add some context to it that might not be normal in your environment. You can add network connections context to look for any scrcons.exe reaching out to external hosts over the network.            |
            

df = spark.sql(
    '''
SELECT d.`@timestamp`, c.Image, d.DestinationIp, d.ProcessId
FROM mordorTable d
INNER JOIN (
    SELECT b.ImageLoaded, a.CommandLine, b.ProcessGuid, a.Image
    FROM mordorTable b
    INNER JOIN (
        SELECT ProcessGuid, CommandLine, Image
        FROM mordorTable
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND Image LIKE '%scrcons.exe'
        ) a
    ON b.ProcessGuid = a.ProcessGuid
    WHERE b.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND b.EventID = 7
        AND LOWER(b.ImageLoaded) IN (
            'c:\\\windows\\\system32\\\wbem\\\scrcons.exe',
            'c:\\\windows\\\system32\\\\vbscript.dll',
            'c:\\\windows\\\system32\\\wbem\\\wbemdisp.dll',
            'c:\\\windows\\\system32\\\wshom.ocx',
            'c:\\\windows\\\system32\\\scrrun.dll'
        )
) c
ON d.ProcessGuid = c.ProcessGuid
WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 3
    '''
)
df.show(10,False)

### Analytic VII


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational', 'Security']          | One of the main goals is to find context that could tell us that scrcons.exe was used over the network (Lateral Movement). One way would be to add a network logon session as context to some of the previous events.            |
            

df = spark.sql(
    '''
SELECT d.`@timestamp`, d.TargetUserName, c.Image, c.ProcessId
FROM mordorTable d
INNER JOIN (
    SELECT b.ImageLoaded, a.CommandLine, b.ProcessGuid, a.Image, b.ProcessId
    FROM mordorTable b
    INNER JOIN (
        SELECT ProcessGuid, CommandLine, Image
        FROM mordorTable
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND Image LIKE '%scrcons.exe'
        ) a
    ON b.ProcessGuid = a.ProcessGuid
    WHERE b.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND b.EventID = 7
        AND LOWER(b.ImageLoaded) IN (
            'c:\\\windows\\\system32\\\wbem\\\scrcons.exe',
            'c:\\\windows\\\system32\\\\vbscript.dll',
            'c:\\\windows\\\system32\\\wbem\\\wbemdisp.dll',
            'c:\\\windows\\\system32\\\wshom.ocx',
            'c:\\\windows\\\system32\\\scrrun.dll'
        )
) c
ON split(d.ProcessId, '0x')[1] = LOWER(hex(CAST(c.ProcessId as INT)))
WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4624
    AND d.LogonType = 3
    '''
)
df.show(10,False)

### Analytic VIII


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Security']          | One of the main goals is to find context that could tell us that scrcons.exe was used over the network (Lateral Movement). One way would be to add a network logon session as context to some of the previous events.            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, TargetUserName,ImpersonationLevel, LogonType, ProcessName
FROM mordorTable
WHERE LOWER(Channel) = "security"
    AND EventID = 4624
    AND LogonType = 3
    AND ProcessName LIKE '%scrcons.exe'
    '''
)
df.show(10,False)

## Detection Blindspots


## Hunter Notes
['Baseline your environment to identify normal activity. Apparently, SCCM leverages WMI event subscriptions.']

## Hunt Output

| Category | Type | Name     |
| :--------| :----| :--------|
| signature | SIGMA | [win_scrcons_remote_wmi_scripteventconsumer](https://github.com/OTRF/ThreatHunter-Playbook/blob/master/signatures/sigma/win_scrcons_remote_wmi_scripteventconsumer.yml) |

## References
* https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf
* https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/scriptingstandardconsumersetting
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/standard-consumer-classes
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/running-a-script-based-on-an-event