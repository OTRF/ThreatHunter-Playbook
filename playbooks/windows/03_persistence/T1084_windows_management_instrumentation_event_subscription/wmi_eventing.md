# WMI Eventing

## Playbook Tags

**ID:** WINPERS190810170510

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:** 

## ATT&CK Tags

**Tactic:** Persistence

**Technique:** Windows Management Instrumentation Event Subscription (T1055)

## Applies To

## Technical Description

WMI is the Microsoft implementation of the Web-Based Enterprise Management (WBEM) and Common Information Model (CIM). Both standards aim to provide an industry-agnostic means of collecting and transmitting information related to any managed component in an enterprise. An example of a managed component in WMI would be a running process, registry key, installed service, file information, etc. At a high level, Microsoft’s implementation of these standards can be summarized as follows: Managed Components Managed components are represented as WMI objects — class instances representing highly structured operating system data. Microsoft provides a wealth of WMI objects that communicate information related to the operating system. E.g. Win32_Process, Win32_Service, AntiVirusProduct, Win32_StartupCommand, etc.

From an offensive perspective WMI has the ability to trigger off nearly any conceivable event, making it a good technique for persistence.

Three requirements
* Filter – An action to trigger off of
* Consumer – An action to take upon triggering the filter
* Binding – Registers a FilterConsumer

Local events run for the lifetime of the host process. Remember that permanent WMI events are persistent and run as SYSTEM.

## Permission Required

Administrator

## Hypothesis

Adversaries might be injecting a dll to another process to execute code via CreateRemoteThread and LoadLibrary functions. 

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_elevated_wmi](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/persistence/wmi_event_subscription_T1084/empire_elevated_wmi.md)  | A mordor dataset to simulate persistence using a permanent WMI subscription |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [19](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-19.md) | WmiEventFilter activity detected | Microsoft-Windows-Sysmon | | |  |
| [20](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-20.md) | WmiEventConsumer activity detected| Microsoft-Windows-Sysmon | | |  |
| [21](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-10.md) | WmiEventConsumerToFilter activity detected | Microsoft-Windows-Sysmon | | |  |
| 5861 | | | | |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Low | Sysmon | SELECT `@timestamp`, computer_name, User, EventNamespace, Name, Query FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 19| Look for WMI event filters registered |
| Low | Sysmon | SELECT `@timestamp`, computer_name, User, Name, Type, Destination FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 20 | Look for WMI event consumers registered |
| Low | Sysmon | SELECT `@timestamp`, computer_name, User, Operation, Consumer, Filter FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 21 | Look for WMI consumers binding to filters |
| Low | Sysmon | SELECT `@timestamp`, computer_name, message FROM mordor_file WHERE channel = "Microsoft-Windows-WMI-Activity/Operational" AND event_id = 5861 | Look for events related to the registration of FilterToConsumerBinding |

## False Positives

## Detection Blind Spots

## Hunter Notes

## Hunt Output

## References

* https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor.pdf
* https://twitter.com/mattifestation/status/899646620148539397
* https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity