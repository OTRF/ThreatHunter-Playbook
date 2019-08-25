# Local Administrator Remote Check via OpenSCManager

## Playbook Tags

**ID:** WINDISC1906241501

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:**

## ATT&CK Tags

**Tactic:** Discovery

**Technique:** Permissions Level Check

## Applies To

## Technical Description

When adversaries get access to a box and are running in the context of a the compromised user session, they might want to know where the user has access to in order to move laterally. One known way to test if the compromised account has local administrator access in any other domain computer is by using the the OpenSCManagerW Win32API call to establish a handle to the remote host. If this succeeds, the current user context has local administrator acess to the target.

The Service Control Manager (SCM) is a remote procedure call (RPC) server, so that service configuration and service control programs can manipulate services on remote machines. The OpenSCManagerW function establishes a connection to the service control manager (SCM) on the specified computer and opens the specified service control manager database.

### Additional Reading

* [Service Control Manager (SCM)](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/library/service_control_manager.md)

## Permission Required

Administrator

## Hypothesis

Adversaries might attempt to use the OpenSCManagerW Win32API call to establish a handle to a remote host to test if the current user has local admin access to remote hosts.

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
| Low | Security | SELECT `@timestamp`, computer_name, SubjectUserName, SubjectLogonId, ProcessName, ObjectName, AccessMask FROM mordor_file WHERE channel = "Security" AND event_id = 4656 AND NOT SubjectLogonId = "0x3e4" AND ObjectName = "ServicesActive" | Look for failure handles to the SCM database from non system user. This event triggers on ServicesActive only when it fails |
| Low | Security | SELECT `@timestamp`, computer_name, SubjectUserName, SubjectLogonId, ProcessName, PrivilegeList, ObjectServer, ObjectName FROM mordor_file WHERE channel = "Security" AND event_id = 4674 AND ObjectType = "SC_MANAGER OBJECT" AND ObjectName = "ServicesActive" AND PrivilegeList = "SeTakeOwnershipPrivilege" AND NOT SubjectLogonId = "0x3e4" | Look for non-system accounts performing privileged operations on protected subsystem objects such as the SCM database |
| Low | Security | SELECT `@timestamp`, computer_name, Application, SourcePort, SourceAddress, DestPort, DestAddress FROM mordor_file WHERE channel = "Security" AND event_id = 5156 AND Application LIKE "%\\\services.exe" AND LayerRTID = 44 | Look for inbound network connections to services.exe from other endpoints in the network |
| High | Sysmon | SELECT `@timestamp`, computer_name, User, SourcePort, SourceIp, DestinationPort, DestinationIp FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 3 AND Image LIKE "%\\\services.exe" | Look for several network connection maded by services.exe from different endpoints to the same destination |
| Low | Security | SELECT o.`@timestamp`, o.computer_name, o.SubjectUserName, o.ObjectType,o.ObjectName, o.PrivilegeList, a.IpAddress FROM mordor_file o INNER JOIN (SELECT computer_name,TargetUserName,TargetLogonId,IpAddress FROM mordor_file WHERE channel = "Security" AND LogonType = 3 AND IpAddress is not null AND NOT TargetUserName LIKE "%$") a ON o.SubjectLogonId = a.TargetLogonId WHERE o.channel = "Security" AND o.event_id = 4674 AND o.ObjectType = "SC_MANAGER OBJECT" AND o.ObjectName = "ServicesActive" AND NOT o.SubjectLogonId = "0x3e4" | Look for non-system accounts performing privileged operations on protected subsystem objects such as the SCM database from other endpoints in the network |

## False Positives

## Detection Blind Spots

## Hunter Notes

* Event id 4656 gets generated only when the OpenSCManager API call fails to get a handle to the SCM database. There is not SACL for SCM database so success attempts will not be logged.
* Event id 4674 gets triggered when the SCM database is accessed. Filter known or common accounts that obtain a handle to SCM on a regular basis (i.e vulnerability scanners)
  * You can join security events 4674 and security events 4624 on the LogonID field and filter results on logon type 3 or network to add more context to your query and look for handles to SCM from remote endpoints.
* You can also join security events 4674 where the object name is `servicesactive` (SCM database) and other security events 4674 on the object handle. This will allow you to map what was actually done after the handle service-wise.
* Event id 5156 gets generated on the target as an inbound network event with process name services.exe. You might have to stack this value based on your environment noise.

## Hunt Output

| Category | Type | Name |
|--------|---------|---------|
| Signature | Sigma Rule | [win_scm_database_handle_failure.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_scm_database_handle_failure.yml) |
| Signature | Sigma Rule | [win_scm_database_privileged_operation.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/win_scm_database_privileged_operation.yml) |

## References

* https://github.com/EmpireProject/Empire/blob/dev/data/module_source/situational_awareness/network/powerview.ps1#L15473