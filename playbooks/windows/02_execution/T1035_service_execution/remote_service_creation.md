# Remote Service Creation

## Playbook Tags

**ID:** WINEXEC190815181010

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:** WINEXEC190813181010

## ATT&CK Tags

**Tactic:** Execution, Lateral Movement

**Technique:** Service Execution (T1035)

## Applies To

## Technical Description

Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager. This can be done by by adversaries creating a new service. Adversaries can create services remotely to execute code and move lateraly across the environment.

## Permission Required

Administrator

## Hypothesis

Adversaries might be creating new services remotely to execute code and move laterally in my environment

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_invoke_psexec](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/execution/service_execution_T1035/empire_invoke_psexec.md) | A mordor dataset to simulate an adversary creating a service |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [4697](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697) | A service was installed in the system | Microsoft-Windows-Security-Auditing | | | Windows Services |
| [4624](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4624.md) | An account was successfully logged on | Microsoft-Windows-Security-Auditing | Audit Logon/Logoff | Audit Logon | Windows Event Logs |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Low | Sysmon | SELECT o.`@timestamp`, o.computer_name, o.SubjectUserName, o.SubjectUserName, o.ServiceName, a.IpAddress FROM mordor_file o INNER JOIN (SELECT computer_name,TargetUserName,TargetLogonId,IpAddress FROM mordor_file WHERE channel = "Security" AND LogonType = 3 AND IpAddress is not null AND NOT TargetUserName LIKE "%$") a ON o.SubjectLogonId = a.TargetLogonId WHERE o.channel = "Security" AND o.event_id = 4697 | Look for new services being created in your environment under a network logon session (3). That is a sign that the service creation was performed from another endpoint in the environment  |

## Detection Blind Spots

## Hunter Notes

* If there are a lot of unique services being created in your environment, try to categorize the data based on the bussiness unit.
* Identify the source of unique services being created everyday. I have seen Microsoft applications doing this.
* Stack the values of the service file name associated with the new service.
* Document what users create new services across your environment on a daily basis

## Hunt Output

## References

* https://www.powershellempire.com/?page_id=523