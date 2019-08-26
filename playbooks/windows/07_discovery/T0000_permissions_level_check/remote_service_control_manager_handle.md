# Remote Service Control Manager Handle

## Playbook Tags

**ID:** WINDISC1908260101

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:**

## ATT&CK Tags

**Tactic:** Discovery

**Technique:** Permissions Level Check

## Applies To

All Windows Versions

## Technical Description

Often times, when an adversary lands on an endpoint, the current user does not have local administrator privileges over the compromised system. While some adversaries consider this situation a dead end, others find it very interesting to identify which machines on the network the current user has administrative access to. One common way to accomplish this is by attempting to open up a handle to the service control manager (SCM) database on remote endpoints in the network with SC_MANAGER_ALL_ACCESS (0xF003F) access rights. 

The Service Control Manager (SCM) is a remote procedure call (RPC) server, so that service configuration and service control programs can manipulate services on remote machines. Only processes with Administrator privileges are able to open a handle to the SCM database. This database is also known as the `ServicesActive database`. Therefore, it is very effective to check if the current user has administrative or local admin access to other endpoints in the network.

An adversary can simply use the Win32 API function [OpenSCManagerA](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagera) to attempt to establish a connection to the service control manager (SCM) on the specified computer and open the service control manager database. If this succeeds (A non-zero handle is returned), the current user context has local administrator acess to the remote host.

### Additional Reading

* [Service Control Manager (SCM)](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/library/service_control_manager.md)

## Permission Required

User, Administrator

## Hypothesis

Adversaries might be attempting to open up a handle to the service control manager (SCM) database on remote endpoints to check for local admin access in my environment.

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_find_local_admin](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/lateral_movement/remote_services_T1021/empire_find_local_admin.md) | A mordor dataset to simulate the use of the OpenSCManagerW Win32API call to establish a handle to a remote host |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [4656](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4656.md) | A handle to an object was requested | Microsoft-Windows-Security-Auditing | Object Access | Kernel Object | Windows Event Logs |
| [4674](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4674) | An operation was attempted on a privileged object | Microsoft-Windows-Security-Auditing | Privilege Use | Sensitive Privilege Use | Windows Event Logs |
| [5156](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156) | The Windows Filtering Platform has permitted a connection. | Microsoft-Windows-Security-Auditing | Object Access | Filtering Platform Connection | Process use of network |
| [3](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-3.md) | Network connection | Microsoft-Windows-Sysmon | | | Process use of network |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Low | Security | SELECT @timestamp, computer_name, SubjectUserName, SubjectLogonId, ProcessName, ObjectName, AccessMask FROM mordor_file WHERE channel = "Security" AND event_id = 4656 AND AccessMask = "0xf003f" AND NOT SubjectLogonId = "0x3e4" AND ObjectName = "ServicesActive" | Look for failure handles to the SCM database from non system user. This event triggers on ServicesActive only when it fails |
| Low | Security | SELECT `@timestamp`, computer_name, SubjectUserName, SubjectLogonId, ProcessName, PrivilegeList, ObjectServer, ObjectName FROM mordor_file WHERE channel = "Security" AND event_id = 4674 AND ObjectType = "SC_MANAGER OBJECT" AND ObjectName = "ServicesActive" AND PrivilegeList = "SeTakeOwnershipPrivilege" AND NOT SubjectLogonId = "0x3e4" | Look for non-system accounts performing privileged operations on protected subsystem objects such as the SCM database |
| Low | Security | SELECT `@timestamp`, computer_name, Application, SourcePort, SourceAddress, DestPort, DestAddress FROM mordor_file WHERE channel = "Security" AND event_id = 5156 AND Application LIKE "%\\\services.exe" AND LayerRTID = 44 | Look for inbound network connections handled by services.exe from other endpoints in the network. Same SourceAddress, but different computer_name |
| High | Sysmon | SELECT `@timestamp`, computer_name, User, SourcePort, SourceIp, DestinationPort, DestinationIp FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 3 AND Image LIKE "%\\\services.exe" | Look for several network connection handled by services.exe from different endpoints to the same destination |
| Low | Security | SELECT o.`@timestamp`, o.computer_name, o.SubjectUserName, o.ObjectType,o.ObjectName, o.PrivilegeList, a.IpAddress FROM mordor_file o INNER JOIN (SELECT computer_name,TargetUserName,TargetLogonId,IpAddress FROM mordor_file WHERE channel = "Security" AND LogonType = 3 AND IpAddress is not null AND NOT TargetUserName LIKE "%$") a ON o.SubjectLogonId = a.TargetLogonId WHERE o.channel = "Security" AND o.event_id = 4674 AND o.ObjectType = "SC_MANAGER OBJECT" AND o.ObjectName = "ServicesActive" AND NOT o.SubjectLogonId = "0x3e4" | Look for non-system accounts performing privileged operations on protected subsystem objects such as the SCM database from other endpoints in the network |

## False Positives

## Detection Blind Spots

## Hunter Notes

* Event id 4656 gets generated only when the OpenSCManager API call fails to get a handle to the SCM database. There is not SACL for SCM database so success attempts will not be logged.
* Event id 4674 gets triggered when the SCM database is accessed. Filter known or common accounts that obtain a handle to SCM on a regular basis (i.e vulnerability scanners)
  * You can join security events 4674 and security events 4624 on the LogonID field and filter results on logon type 3 or network to add more context to your query and look for handles to SCM from remote endpoints.
  * Look for the same endpoint or IP address to many remote hosts to find potential aggressive attempts.
* You can also join security events 4674 where the object name is `servicesactive` (SCM database) with other security events on the object handle. This will allow you to identify what was actually done after the handle was opened. For example, the same handle can be used to create a service (i.e. PSEXESVC)
* Event id 5156 gets generated on the target as an inbound network event with process name services.exe. You might have to stack the `SourceAddress` field value based on your environment noise.

## Hunt Output

| Category | Type | Name |
|--------|---------|---------|
| Signature | Sigma Rule | [win_scm_database_handle_failure.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_scm_database_handle_failure.yml) |
| Signature | Sigma Rule | [win_scm_database_privileged_operation.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_scm_database_privileged_operation.yml) |

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