# WMI Module Load

## Playbook Tags

**ID:** WINEXEC190811201010

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:**

## ATT&CK Tags

**Tactic:** Execution

**Technique:** Windows Management Instrumentation (T1047)

## Applies To

## Technical Description

WMI is the Microsoft implementation of the Web-Based Enterprise Management (WBEM) and Common Information Model (CIM). Both standards aim to provide an industry-agnostic means of collecting and transmitting information related to any managed component in an enterprise. An example of a managed component in WMI would be a running process, registry key, installed service, file information, etc. At a high level, Microsoft’s implementation of these standards can be summarized as follows: Managed Components Managed components are represented as WMI objects — class instances representing highly structured operating system data. Microsoft provides a wealth of WMI objects that communicate information related to the operating system. E.g. Win32_Process, Win32_Service, AntiVirusProduct, Win32_StartupCommand, etc.

WMI modules loaded by legit processes such as wmiprvse.exe or wmiapsrv.exe are the following:

* C:\Windows\System32\wmiclnt.dll      
* C:\Windows\System32\wbem\WmiApRpl.dll
* C:\Windows\System32\wbem\wmiprov.dll
* C:\Windows\System32\wbem\wmiutils.dll
* C:\Windows\System32\wbemcomn.dll
* C:\Windows\System32\wbem\wbemprox.dll
* C:\Windows\Microsoft.NET\Framework64\v2.0.50727\WMINet_Utils.dll
* C:\Windows\System32\wbem\wbemsvc.dll
* C:\Windows\System32\wbem\fastprox.dll

Adversaries could leverage the WMI modules above to execute WMI tasks bypassing controls looking for wmiprvse.exe or wmiapsrv.exe activity.

## Permission Required

User

## Hypothesis

Adversaries might be leveraging WMI modules to execute WMI tasks bypassing controls monitoring for wmiprvse.exe or wmiapsrv.exe activity

## Attack Simulation Dataset

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_psinject](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/defense_evasion/process_injection_T1055/empire_psinject.md) | A mordor dataset to simulate the use of WMI modules loaded by unknown processes |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| [7](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-7.md) | Image Loaded | Microsoft-Windows-Sysmon | | | Loaded DLLs |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| Low | Sysmon | SELECT `@timestamp`, computer_name, Image, ImageLoaded FROM mordor_file WHERE channel = "Microsoft-Windows-Sysmon/Operational" AND event_id = 7 AND (lower(ImageLoaded) LIKE "%wmiclnt.dll" OR lower(ImageLoaded) LIKE "%WmiApRpl.dll" OR lower(ImageLoaded) LIKE "%wmiprov.dll" OR lower(ImageLoaded) LIKE "%wmiutils.dll" OR lower(ImageLoaded) LIKE "%wbemcomn.dll" OR lower(ImageLoaded) LIKE "%WMINet_Utils.dll" OR lower(ImageLoaded) LIKE "%wbemsvc.dll" OR lower(ImageLoaded) LIKE "%fastprox.dll" OR lower(Description) LIKE "%wmi%") AND NOT (lower(Image) LIKE "%wmiprvse.exe" OR lower(Image) LIKE "%wmiapsrv.exe" OR lower(Image) LIKE "%svchost.exe")| Look for processes (non wmiprvse.exe or WmiApSrv.exe) loading wmi modules |

## Detection Blind Spots

## Hunter Notes

* Stack the processes loading WMI modules and document the activity in your environment.
* Stack child processes (if any) of non wmiprvse.exe loading wmi modules
* Look for WMI descriptions in case the DLLs are renamed

## Hunt Output

| Category | Type | Name |
|--------|---------|---------|
| Signature | Sigma Rule | [sysmon_wmi_module_load.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_wmi_module_load.yml) |

## References

* https://posts.specterops.io/threat-hunting-with-jupyter-notebooks-part-4-sql-join-via-apache-sparksql-6630928c931e
* https://posts.specterops.io/real-time-sysmon-processing-via-ksql-and-helk-part-3-basic-use-case-8fbf383cb54f