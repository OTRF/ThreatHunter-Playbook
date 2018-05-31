# AppInit DLLs
## Technique ID
T1103


## Description
DLLs that are specified in the AppInit_DLLs value in the Registry key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program. This value can be abused to obtain persistence by causing a DLL to be loaded into most processes on the computer. The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled.


## Hypothesis
Adversaries are using the AppInit_DLL functionality in my environment to achieve persistence.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [AppInit\_DLL](https://github.com/redcanaryco/atomic-red-team/blob/225f39bbb5799fba6b8e8bdada152dd178bf2174/atomics/T1103/T1103.md#atomic-test-1---install-appinit-shim)| AppInit\_DLLs is a mechanism that allows an arbitrary list of DLLs to be loaded into each user mode process on the system.| [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/225f39bbb5799fba6b8e8bdada152dd178bf2174/atomics/T1103/T1103.md#atomic-test-1---install-appinit-shim) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Registry Monitoring| Sysmon |



## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 13 | TargetObject | HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs | [Eric Merritt](https://www.trustwave.com/Resources/SpiderLabs-Blog/Shining-the-Spotlight-on-Cherry-Picker-PoS-Malware/) |
| Sysmon | 13 | Details | %APPDATA%\\..\\[name].dll (Optional Path) | [Eric Merritt](https://www.trustwave.com/Resources/SpiderLabs-Blog/Shining-the-Spotlight-on-Cherry-Picker-PoS-Malware/) |
| Sysmon | 13 | TargetObject | HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs | [Eric Merritt](https://www.trustwave.com/Resources/SpiderLabs-Blog/Shining-the-Spotlight-on-Cherry-Picker-PoS-Malware/) |
| Sysmon | 13 | Details | DWORD (0x00000001) (If it is not already enabled) | [Eric Merritt](https://www.trustwave.com/Resources/SpiderLabs-Blog/Shining-the-Spotlight-on-Cherry-Picker-PoS-Malware/) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| appinit\_dlls | Sysmon configuration | [TT1103_appinit_dlls.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/TT1103_appinit_dlls.xml)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier |  TBD  | [registry]\(TBD\) |


## Hunter Notes
* Look for values being set to AppInit_DLLs keys and compare it with the rest of your environment (If it is something that needs to be changed constantly or from time to time. doubt it)
* LoadAppInit_DLLs being turned on when is not supposed to could lead to an investigation and great to start a hunt for persistence. 


## Hunting Techniques Recommended

- [ ] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests