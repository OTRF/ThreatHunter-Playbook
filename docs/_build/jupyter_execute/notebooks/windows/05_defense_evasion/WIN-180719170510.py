# DLL Injection via CreateRemoteThread and LoadLibrary

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-180719170510 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2018/07/19 |
| platform      | Windows |
| playbook link |  |
        

## Technical Description
This technique is one of the most common techniques used to inject malware into another process.
The malware writes the path to its malicious dynamic-link library (DLL) in the virtual address space of another process, and ensures the remote process loads it by creating a remote thread in the target process.

### Get Handle to Target Processs
The malware first needs to target a process for injection (e.g. svchost.exe).
This is usually done by searching through processes by calling a trio of Application Program Interfaces (APIs) > CreateToolhelp32Snapshot, Process32First, and Process32Next.
After finding the target process, the malware gets the handle of the target process by calling OpenProcess.

There are two processes involved in this attack > your DLLInjector process (Process A), and the remote process you want to inject with a DLL (Process B).
To interact with the remote process, Process A must call OpenProcess() while passing the remote process’s process ID as an argument. OpenProcess will then return to Process A a Handle to Process B.
Having a Handle to the remote process allows Process A to interact with it in powerful ways. Process A can allocate memory, write memory, and create an execution thread in Process B by calling functions like VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread and passing the Handle to Process B as an argument to those functions.

### Get address of the LoadLibraryA function
Kernel32.dll is loaded into every Windows process, and within it is a useful function called LoadLibrary.
When LoadLibrary is called in a certain process, it maps a DLL into that process.
LoadLibrary needs to know what DLL to load, so you need to provide it the path to the DLL on your system.
LoadLibrary will then find the DLL at that path and load that DLL into memory for you.
Note > LoadLibraryA is the function name. “A” means you provide the DLL path as an ASCII string.

### Allocate Memory for DLL
Why do we write the DLL path to Process B using VirtualAllocEx and then WriteRemoteMemory? This is because LoadLibrary needs to know what DLL you want to inject.
The string it accepts as a parameter needs to be present in Process B’s memory.
The malware calls VirtualAllocEx to have a space to write the path to its DLL.
The malware then calls WriteProcessMemory to write the path in the allocated memory.

### Execute Code
Finally, to have the code executed in another process, the malware calls APIs such as CreateRemoteThread, NtCreateThreadEx, or RtlCreateUserThread.
The latter two are undocumented. However, the general idea is to pass the address of LoadLibrary to one of these APIs so that a remote process has to execute the DLL on behalf of the malware.
The CreateRemoteThread function creates a thread in the virtual address space of an arbitrary process.

Use CreateRemoteThread to create a remote thread starting at the memory address (which means this will execute LoadLibrary in the remote process).
Besides the memory address of the remote function you want to call, CreateRemoteThread also allows you to provide an argument for the function if it requires one.
LoadLibrary wants the memory address of where you wrote that DLL path from earlier, so provide CreateRemoteThread that address as well.

## Hypothesis
Adversaries might be injecting a dll to another process to execute code via CreateRemoteThread and LoadLibrary functions.

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/defense_evasion/empire_dll_injection.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| High       | ['Microsoft-Windows-Sysmon/Operational']          | Look for any use of the CreateRemoteThread function to create a remote thread starting at the memory address (which means this will execute LoadLibrary in the remote process)            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, SourceImage, TargetImage
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 8
    AND lower(StartModule) LIKE "%kernel32.dll"
    AND StartFunction = "LoadLibraryA"
    '''
)
df.show(10,False)

### Analytic II


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Medium       | ['Microsoft-Windows-Sysmon/Operational']          | You can look for the same file being created and loaded. The process that creates the file and loads the file are not the same.            |
            

df = spark.sql(
    '''
SELECT f.`@timestamp` AS file_date, m.`@timestamp` AS module_date, f.computer_name, f.Image AS file_image, m.Image AS module_image, m.ImageLoaded, f.TargetFilename
FROM mordorTable f
INNER JOIN (
    SELECT `@timestamp`,computer_name,Image,ImageLoaded,TargetLogonId,IpAddress
    FROM mordorTable
    WHERE channel = "Microsoft-Windows-Sysmon/Operational"
        AND event_id = 7
    ) m
ON f.TargetFilename = m.ImageLoaded
WHERE f.channel = "Microsoft-Windows-Sysmon/Operational"
    AND f.event_id = 11
    AND f.computer_name = m.computer_name
    '''
)
df.show(10,False)

## Detection Blindspots
Instead of passing the address of the LoadLibrary, adversaries can copy the malicious code into an existing open process and cause it to execute (either via a small shellcode, or by calling CreateRemoteThread) via a technique known as PE injection.
The advantage of this is that the adversary does not have to drop a malicious DLL on the disk.
Similar to the basic dll injection technique, the malware allocates memory in a host process (e.g. VirtualAllocEx), and instead of writing a “DLL path” it writes its malicious code by calling WriteProcessMemory.

## Hunter Notes
* Looking for CreateRemoteThread APIs with LoadLibrary functions might return several entries in your environment. I recommend to stack the values of the source and target processes or user to baseline your environmennt.
* Look for processes loading files that have just been created on disk (i.e 1min time window). Stack the values of the processes and files involved. You can tag the files as signed or unsigned depending on the information provided in the security events.

## Hunt Output

| Category | Type | Name     |
| :--------| :----| :--------|
| signature | SIGMA | [sysmon_createremotethread_loadlibrary](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_createremotethread_loadlibrary.yml) |

## References
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
* https://resources.infosecinstitute.com/using-createremotethread-for-dll-injection-on-windows/
* https://arvanaghi.com/blog/dll-injection-using-loadlibrary-in-C/
* https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution/Invoke-DllInjection.ps1#L249
* https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution/Invoke-DllInjection.ps1#L291
* https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution/Invoke-DllInjection.ps1#L295
* https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution/Invoke-DllInjection.ps1#L303
* https://github.com/EmpireProject/Empire/blob/master/data/module_source/code_execution/Invoke-DllInjection.ps1#L307
* https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya