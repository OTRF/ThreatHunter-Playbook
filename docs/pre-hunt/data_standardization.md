# Data Standardization

The data standardization process relies heavily on the use of a Common Information Model (CIM) in order to facilitate the normalization of data sets via a standard way to parse data. A common schema helps hunters to correlate data from diverse data sources, and avoid writing long queries trying to hit every possible name assigned to a field that provides the same information across several data sources.

## What is a Common Information Model (CIM)?
An information model describes the things in a domain in terms of objects, their properties
(represented as attributes), and their relationships. [source](https://www.opennetworking.org/wp-content/uploads/2014/10/TR-513_CIM_Overview_1.2.pdf)

## Why?
Understanding the standardization of events and their respective field names help hunters tremendously when developing data analytics. This activity along with data documentation help hunt teams to identify data sources that might be available but not being considered in the data scope while running analytics in production. For example, if an analytic is using the field **"process_name"** , but it is named **"processName"** or **"ImageName"** in several other data sources available, the the data scope will be limited and will eventually affect the fidelity of the analytic.

## How?
I recommend to first understand what it is that you are collecting. This is why the **Documentation** stage is very helpful and important to do either in parallel or before this activity.

### Define Data Objects
You should start by identifiying **"Data Objects"** in the data that you collect in the cyber domain. A CIM object is a representation of entities found across several security events such as:

* Process
* User
* E-mail
* IP Address

### Define Data Object Properties
Defining data objects allow you to categorize/group event fields and be able to define a specific schema for each data object. For example, a **"Process"** data object can have properties such as:

* process_name
* process_command_line
* process_guid
* process_id

one example for **"Process"** can be found in the [OSSEM Common Data Model project](https://github.com/OTRF/OSSEM-CDM/blob/master/schemas/entities/process.yml)

### Apply CIM to Events
Next, you can take the schemas defined for each data object and apply them to event logs you collect.

* For example, let's say we have this event from Sysmon (Event ID 1):

```
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>1</EventID> 
    <Version>5</Version> 
    <Level>4</Level> 
    <Task>1</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-06-12T00:48:53.300422700Z" /> 
    <EventRecordID>6526518</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="2312" ThreadID="3800" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>DESKTOP-WARDOG.RIVENDELL.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  <EventData>
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
  </EventData>
</Event>
```

* We could easily standardize its event fields and combine them with data dictionaries as shown in [here](https://github.com/OTRF/OSSEM-DD/blob/main/windows/sysmon/events/event-1.yml) by the [OSSEM project](https://github.com/OTRF/OSSEM).

## When?
Depending on your priorities and the resources allocated to your team, you can either start your own CIM based on all the data soures available at once, or gradually create it from each data sources used as you build analytics.

## References:

* https://docs.oracle.com/cd/E19683-01/806-6827/6jfoa8m6v/index.html
* https://github.com/OTRF/OSSEM
