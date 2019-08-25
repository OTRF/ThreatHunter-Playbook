# Service Creation

## Playbook Tags

**ID:** WINEXEC190813181010

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:**

## ATT&CK Tags

**Tactic:** Execution

**Technique:** Service Execution (T1035)

## Applies To

## Technical Description

Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager. This can be done by by adversaries creating a new service. 

## Permission Required

Administrator

## Hypothesis

Adversaries might be creating new services to execute code on a compromised endpoint in my environment

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_invoke_psexec](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/execution/service_execution_T1035/empire_invoke_psexec.md) | A mordor dataset to simulate an adversary creating a service |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [4697](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697) | A service was installed in the system | Microsoft-Windows-Security-Auditing | | | Windows Services |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Low | Sysmon | SELECT `@timestamp`, computer_name, SubjectUserName ServiceName, ServiceType, ServiceStartType, ServiceAccount FROM mordor_file WHERE channel = "Security"AND event_id = 4697| Look for new services being created in your environment and stack the values of it |

## False Positives

## Detection Blind Spots

## Hunter Notes

* If there are a lot of unique services being created in your environment, try to categorize the data based on the bussiness unit.
* Identify the source of unique services being created everyday. I have seen Microsoft applications doing this.
* Stack the values of the service file name associated with the new service.
* Document what users create new services across your environment on a daily basis

## Hunt Output

## References

* https://www.powershellempire.com/?page_id=523