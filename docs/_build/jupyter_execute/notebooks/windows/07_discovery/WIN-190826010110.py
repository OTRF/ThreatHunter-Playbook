# Remote Service Control Manager Handle

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-190826010110 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2019/08/26 |
| platform      | Windows |
| playbook link |  |
        

## Technical Description
Often times, when an adversary lands on an endpoint, the current user does not have local administrator privileges over the compromised system.
While some adversaries consider this situation a dead end, others find it very interesting to identify which machines on the network the current user has administrative access to.
One common way to accomplish this is by attempting to open up a handle to the service control manager (SCM) database on remote endpoints in the network with SC_MANAGER_ALL_ACCESS (0xF003F) access rights.
The Service Control Manager (SCM) is a remote procedure call (RPC) server, so that service configuration and service control programs can manipulate services on remote machines.
Only processes with Administrator privileges are able to open a handle to the SCM database.
This database is also known as the ServicesActive database.
Therefore, it is very effective to check if the current user has administrative or local admin access to other endpoints in the network.
An adversary can simply use the Win32 API function [OpenSCManagerA](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagera) to attempt to establish a connection to the service control manager (SCM) on the specified computer and open the service control manager database.
If this succeeds (A non-zero handle is returned), the current user context has local administrator acess to the remote host.

Additional reading
* https://github.com/hunters-forge/ThreatHunter-Playbook/tree/master/docs/library/service_control_manager.md

## Hypothesis
Adversaries might be attempting to open up a handle to the service control manager (SCM) database on remote endpoints to check for local admin access in my environment.

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/hunters-forge/mordor/master/datasets/small/windows/discovery/empire_find_local_admin.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Security']          | Detects non-system users failing to get a handle of the SCM database.            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, SubjectUserName, ProcessName, ObjectName
FROM mordorTable
WHERE channel = "Security"
    AND event_id = 4656
    AND ObjectType = "SC_MANAGER OBJECT"
    AND ObjectName = "ServicesActive"
    AND AccessMask = "0xf003f"
    AND NOT SubjectLogonId = "0x3e4"
    '''
)
df.show(10,False)

### Analytic II


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Security']          | Look for non-system accounts performing privileged operations on protected subsystem objects such as the SCM database            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, SubjectUserName, ProcessName, ObjectName, PrivilegeList, ObjectServer
FROM mordorTable
WHERE channel = "Security"
    AND event_id = 4674
    AND ObjectType = "SC_MANAGER OBJECT"
    AND ObjectName = "ServicesActive"
    AND PrivilegeList = "SeTakeOwnershipPrivilege"
    AND NOT SubjectLogonId = "0x3e4"
    '''
)
df.show(10,False)

### Analytic III


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Security']          | Look for inbound network connections to services.exe from other endpoints in the network. Same SourceAddress, but different computer_name            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, Application, SourcePort, SourceAddress, DestPort, DestAddress
FROM mordorTable
WHERE channel = "Security"
    AND event_id = 5156
    AND Application LIKE "%\\\services.exe"
    AND LayerRTID = 44
    '''
)
df.show(10,False)

### Analytic IV


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| High       | ['Microsoft-Windows-Sysmon/Operational']          | Look for several network connection maded by services.exe from different endpoints to the same destination            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, User, SourcePort, SourceIp, DestinationPort, DestinationIp
FROM mordorTable
WHERE channel = "Microsoft-Windows-Sysmon/Operational"
    AND event_id = 3
    AND Image LIKE "%\\\services.exe"
    '''
)
df.show(10,False)

### Analytic V


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Security']          | Look for non-system accounts performing privileged operations on protected subsystem objects such as the SCM database from other endpoints in the network            |
            

df = spark.sql(
    '''
SELECT o.`@timestamp`, o.computer_name, o.SubjectUserName, o.ObjectType,o.ObjectName, o.PrivilegeList, a.IpAddress
FROM mordorTable o
INNER JOIN (
    SELECT computer_name,TargetUserName,TargetLogonId,IpAddress
    FROM mordorTable
    WHERE channel = "Security"
        AND LogonType = 3
        AND IpAddress is not null
        AND NOT TargetUserName LIKE "%$"
    ) a
ON o.SubjectLogonId = a.TargetLogonId
WHERE o.channel = "Security"
    AND o.event_id = 4674
    AND o.ObjectType = "SC_MANAGER OBJECT"
    AND o.ObjectName = "ServicesActive"
    AND NOT o.SubjectLogonId = "0x3e4"
    '''
)
df.show(10,False)

## Detection Blindspots


## Hunter Notes
* Event id 4656 gets generated only when the OpenSCManager API call fails to get a handle to the SCM database. There is not SACL for SCM database so success attempts will not be logged.
* Event id 4674 gets triggered when the SCM database is accessed. Filter known or common accounts that obtain a handle to SCM on a regular basis (i.e vulnerability scanners)
* You can join security events 4674 and security events 4624 on the LogonID field and filter results on logon type 3 or network to add more context to your query and look for handles to SCM from remote endpoints.
* Look for the same endpoint or IP address to many remote hosts to find potential aggressive attempts.
* You can also join security events 4674 where the object name is servicesactive (SCM database) with other security events on the object handle. This will allow you to identify what was actually done after the handle was opened. For example, the same handle can be used to create a service (i.e. PSEXESVC)
* Event id 5156 gets generated on the target as an inbound network event with process name services.exe. You might have to stack the SourceAddress field value based on your environment noise.

## Hunt Output

| Category | Type | Name     |
| :--------| :----| :--------|
| signature | SIGMA | [win_scm_database_handle_failure](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_scm_database_handle_failure.yml) |
| signature | SIGMA | [win_scm_database_privileged_operation](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_scm_database_privileged_operation.yml) |

## References
* https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
* https://github.com/EmpireProject/Empire/blob/dev/data/module_source/situational_awareness/network/powerview.ps1#L15473
* https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb#L217
* https://github.com/nettitude/PoshC2_Python/blob/master/Modules/Get-System.ps1#L222
* https://www.pentestgeek.com/metasploit/find-local-admin-with-metasploit
* http://www.harmj0y.net/blog/penetesting/finding-local-admin-with-the-veil-framework/
* https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory
* https://docs.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicebase.servicehandle?view=netframework-4.8
* https://community.rsa.com/community/products/netwitness/blog/2019/04/10/detecting-lateral-movement-in-rsa-netwitness-winexe