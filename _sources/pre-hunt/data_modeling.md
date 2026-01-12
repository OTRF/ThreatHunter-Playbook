# Data Modeling

A data model basically determines the structure of data and the relationships identified among each other. Identifying relationships among security events is very important to document specific events that could map to specific chain of events related to adversaries behaviors. Mitre ATT&CK created its [own data model](https://car.mitre.org/data_model/) strongly inspired by [STIX Cyber Obserbale Objects](http://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part4-cyber-observable-objects.html).

## Why?
We can model Sysmon events and find that almost all its events can be correlated by the **ProcessGUID** field. If we visualize those relationships, we get the following image:

![](../images/SYSMON_DATA_MODEL.png)

We can then use that model and start mapping events to adversarial activity. For example, we can map Windows Management Instrumentation (WMI) spawning a new process that makes a network connection to communicate with an external network entity to specific Sysmon event logs joined by their **ProcessGUID** value.

![](../images/SYSMON_WMI_MODEL.png)

## How?

### Document Security Events
First, you need to have a good understanding of the events you are collecting. Therefore, I highly recommend to start **documenting** every single data source you are ingesting or at least the events being considered for the development of an analytic.

### Identify Relationships
Each event log collected is triggered by a specific action, and each event contains a specific structure and data elements that represent data objects in the Cyber domain such as a process, IP address, e-mail, user, etc.

For example, [Windows Sysmon Event ID 1](https://github.com/OTRF/OSSEM-DD/blob/main/windows/sysmon/events/event-1.yml) is triggered when a **Process** is created, and contains the following information:

```
<Data Name="RuleName" /> 
<Data Name="UtcTime">2019-06-12 00:48:53.295</Data> 
<Data Name="ProcessGuid">{A98268C1-4BF5-5D00-0000-00102A7B2B00}</Data> 
<Data Name="ProcessId">6364</Data> 
<Data Name="Image">C:\Windows\System32\wuauclt.exe</Data> 
<Data Name="FileVersion">10.0.17134.1 (WinBuild.160101.0800)</Data> 
<Data Name="Description">Windows Update</Data> 
<Data Name="Product">Microsoft® Windows® Operating System</Data> 
<Data Name="Company">Microsoft Corporation</Data> 
<Data Name="OriginalFileName">wuauclt.exe</Data> 
<Data Name="CommandLine">"C:\WINDOWS\system32\wuauclt.exe" /RunHandlerComServer</Data> 
<Data Name="CurrentDirectory">C:\WINDOWS\system32\</Data> 
<Data Name="User">NT AUTHORITY\SYSTEM</Data> 
<Data Name="LogonGuid">{A98268C1-48F4-5D00-0000-0020E7030000}</Data> 
<Data Name="LogonId">0x3e7</Data> 
<Data Name="TerminalSessionId">0</Data> 
<Data Name="IntegrityLevel">System</Data> 
<Data Name="Hashes">IMPHASH=E799C2BD8BC66603D6DDC95F2DB31A18</Data> 
<Data Name="ParentProcessGuid">{A98268C1-48F5-5D00-0000-00103C410100}</Data> 
<Data Name="ParentProcessId">1040</Data> 
<Data Name="ParentImage">C:\Windows\System32\svchost.exe</Data> 
<Data Name="ParentCommandLine">C:\WINDOWS\system32\svchost.exe -k netsvcs -p</Data>
```

Based on the definition and data structure of the Sysmon event ID 1 provided above, we can say:

* **Process svchost.exe** [ CREATED ] **Process wuauclt.exe**

Understanding events at this level allows you to map data relationships to specific event logs and expedite the development of analytics.

### Document Relationships
Once you identify those relationships, start documenting them in a way that it is easy for others to read. One perfect example is [this document](https://github.com/OTRF/OSSEM-DM/blob/main/use-cases/mitre_attack/attack_events_mapping.csv) developed in the [OSSEM Detection Model project](https://github.com/OTRF/OSSEM-DM) that shows relationships identified on several Windows event logs.

![](../images/DATA_MODELING_TABLE.png)

### Model Adversary Behavior
Once you have a good understanding of the relationships identified in the security events that you are working with to develop an analytic, you can start mapping adversary behavior to security events in an easier and more intuitive way as shown below.

![](../images/DATA_MODELING_ADVERSARY.png)

## When?
Usually data modeling happens while researching ways to detect adversarial behavior. However, you could start early and start documenting relationships in security event logs while creating data dictionaries.

Once again, documenting event logs structure and identifying relationships among them is a very important exercise before writing queries. It would help you to find potential correlations that you might have not been aware before. You could also benefit from the extra context identified during this exercise and develop more robust data analytics.

## References:

* http://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part4-cyber-observable-objects.html
* https://github.com/OTRF/OSSEM-DM/blob/main/use-cases/mitre_attack/attack_events_mapping.csv
