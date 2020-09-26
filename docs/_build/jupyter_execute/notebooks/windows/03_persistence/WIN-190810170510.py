# WMI Eventing

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2019/08/10 |
| modification date | 2020/09/20 |
| playbook related  | [] |

## Hypothesis
Adversaries might be leveraging WMI eventing for persistence in my environment.

## Technical Context
WMI is the Microsoft implementation of the Web-Based Enterprise Management (WBEM) and Common Information Model (CIM). Both standards aim to provide an industry-agnostic means of collecting and transmitting information related to any managed component in an enterprise.
An example of a managed component in WMI would be a running process, registry key, installed service, file information, etc.
At a high level, Microsoft’s implementation of these standards can be summarized as follows > Managed Components Managed components are represented as WMI objects — class instances representing highly structured operating system data. Microsoft provides a wealth of WMI objects that communicate information related to the operating system. E.g. Win32_Process, Win32_Service, AntiVirusProduct, Win32_StartupCommand, etc.

## Offensive Tradecraft
From an offensive perspective WMI has the ability to trigger off nearly any conceivable event, making it a good technique for persistence.

Three requirements
* Filter – An action to trigger off of
* Consumer – An action to take upon triggering the filter
* Binding – Registers a FilterConsumer

## Mordor Test Data


|           |           |
|:----------|:----------|
| metadata  | https://mordordatasets.com/notebooks/small/windows/03_persistence/SDWIN-190518184306.html        |
| link      | [https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user.zip](https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user.zip)  |

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor Dataset

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user.zip"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I
Look for WMI event filters registered


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| WMI object | Microsoft-Windows-Sysmon/Operational | User created Wmi filter | 19 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, User, EventNamespace, Name, Query
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 19
'''
)
df.show(10,False)

### Analytic II
Look for WMI event consumers registered


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| WMI object | Microsoft-Windows-Sysmon/Operational | User created Wmi consumer | 20 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, User, Name, Type, Destination
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 20
'''
)
df.show(10,False)

### Analytic III
Look for WMI consumers binding to filters


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| WMI object | Microsoft-Windows-Sysmon/Operational | User created Wmi subscription | 21 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, User, Operation, Consumer, Filter
FROM mordorTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 21
'''
)
df.show(10,False)

### Analytic IV
Look for events related to the registration of FilterToConsumerBinding


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| WMI object | Microsoft-Windows-WMI-Activity/Operational | Wmi subscription created | 5861 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, Message
FROM mordorTable
WHERE Channel = "Microsoft-Windows-WMI-Activity/Operational"
    AND EventID = 5861
'''
)
df.show(10,False)

## Known Bypasses


| Idea | Playbook |
|:-----|:---------|

## False Positives
None

## Hunter Notes
None

## Hunt Output

| Type | Link |
| :----| :----|

## References
* https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor.pdf
* https://twitter.com/mattifestation/status/899646620148539397
* https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity