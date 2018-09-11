# Bypassing Application Whitelisting with Regsvr32.exe
## Technique ID
T1117


## Description
Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe can be used to execute arbitrary binaries. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of whitelists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe is also a Microsoft signed binary.Regsvr32.exe can also be used to specifically bypass process whitelisting using functionality to load COM scriptlets to execute DLLs under user permissions. Since regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed


## Hypothesis
Adversaries might be bypassing our application whitelisting controls by using Regsvr32.exe in order to download and execute malicious binaries or scripts.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [Regsvr32](https://github.com/redcanaryco/atomic-red-team/blob/a0bda9537a3486c3a0fa826419772ebcfb8cc619/atomics/T1117/T1117.md)| Local DLL, COM, and Remote COM execution|[atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/a0bda9537a3486c3a0fa826419772ebcfb8cc619/atomics/T1117/T1117.md) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring|Sysmon|
|Process Monitoring |WinEvent | 



## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | Image OR ParentImage| C:\Windows\System\32\regsvr32.exe | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g), [Keshia LeVan](https://www.redcanary.com/blog/whitelist-evasion-example-threat-detection-723) |
| Sysmon | 1 | CommandLine OR ParentCommandLine | scrobj.dll AND (/s /n /u /i OR /i OR http) | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g), [Keshia LeVan](https://www.redcanary.com/blog/whitelist-evasion-example-threat-detection-723) |



## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Regsvr32 | Sysmon Configuration | [T1117_regsvr32.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T1117_regsvr32.xml)


## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
|Anomaly/Outlier | process WHERE process\_parent\_name == "regsvr32.exe" AND process\_name == "*" | [process](https://github.com/bfuzzy/OSSEM/blob/master/detection_data_model/data_objects/process.md) | 


## Hunter Notes
* We are looking for outliers in here so stacking is a good technique to use. The key is to return a managable number of results to keep digging.
* If you know your network, you will be able to spot malicious scripts or binaries being downloaded and executed.
* http will cover http & https.
* regsvr32.exe is uncommon as a parent process unless it is executing C:\Windows\SysWOW64\regsvr32.exe.
  * Stack regsvr32.exe as a ParentImage and look at the anomalies


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [X] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
