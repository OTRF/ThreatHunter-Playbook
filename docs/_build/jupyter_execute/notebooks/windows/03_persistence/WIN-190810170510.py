# WMI Eventing

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-190810170510 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2019/08/10 |
| platform      | Windows |
| playbook link |  |
        

## Technical Description
WMI is the Microsoft implementation of the Web-Based Enterprise Management (WBEM) and Common Information Model (CIM). Both standards aim to provide an industry-agnostic means of collecting and transmitting information related to any managed component in an enterprise.
An example of a managed component in WMI would be a running process, registry key, installed service, file information, etc.
At a high level, Microsoft’s implementation of these standards can be summarized as follows > Managed Components Managed components are represented as WMI objects — class instances representing highly structured operating system data. Microsoft provides a wealth of WMI objects that communicate information related to the operating system. E.g. Win32_Process, Win32_Service, AntiVirusProduct, Win32_StartupCommand, etc.

From an offensive perspective WMI has the ability to trigger off nearly any conceivable event, making it a good technique for persistence.

Three requirements
* Filter – An action to trigger off of
* Consumer – An action to take upon triggering the filter
* Binding – Registers a FilterConsumer

## Hypothesis
Adversaries might be leveraging WMI eventing for persistence in my environment.

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/hunters-forge/mordor/master/datasets/small/windows/persistence/empire_elevated_wmi.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational']          | Look for WMI event filters registered            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, User, EventNamespace, Name, Query
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 19
    '''
)
df.show(10,False)

### Analytic II


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational']          | Look for WMI event consumers registered            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, User, Name, Type, Destination
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 20
    '''
)
df.show(10,False)

### Analytic III


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational']          | Look for WMI consumers binding to filters            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, User, Operation, Consumer, Filter
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 21
    '''
)
df.show(10,False)

### Analytic IV


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Microsoft-Windows-Sysmon/Operational']          | Look for events related to the registration of FilterToConsumerBinding            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, message
FROM mordorTable
WHERE channel = "Microsoft-Windows-WMI-Activity/Operational"
    AND event_id = 5861
    '''
)
df.show(10,False)

## Detection Blindspots


## Hunter Notes


## Hunt Output


## References
* https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor.pdf
* https://twitter.com/mattifestation/status/899646620148539397
* https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity