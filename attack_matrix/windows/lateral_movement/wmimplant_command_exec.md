# WMImplant Command_Exec
## Technique ID
T0000_wmimplant


## Description
A PowerShell based tool that leverages WMI to both perform actions against targeted machines, but also as the C2 channel for issuing commands and receiving results. The **command_exec** command is part of the **Lateral Movement Facilitation Commands** section which allows an adversary to run command lines remotely with compromised credentials.


## Hypothesis
Adversaries might be executing WMImplant in my environment in order to facilitate lateral movement by running commands remotely with compromised credentials.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| \[TBD\](TBD)| TBD | \[TBD\](TBD) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring|Sysmon|
|Process Monitoring|WinEvent| 


## Specific Events
| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 1 | ParentImage | wmiprvse.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_26.html) |
| Sysmon | 1 | Image OR ParentImage | powershell.exe (Could be renamed) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_26.html) |
| Sysmon | 1 | ParentCommandLine OR CommandLine | 'Get-C\`hildItem', 'Get-C\`ommand', 'DI\`R', 'L\`S', 'Child\`Item', 'Inv\`oke-Ex\`pression', 'IE\`X', 'G\`CI', env:, 'Co\`mmand' | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_26.html) |
| Sysmon | 12, 13 | TargetObject | Pattern: \\Environment\\[a-zA-Z0-9]{5} | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_26.html) |
| Sysmon | 13 | Details | 'Win32_OSRecoveryConfiguration', 'DebugFilePath' | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_26.html) |
| Sysmon | 17, 18 | PipeName | \<Anonymous Pipes\> | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_26.html) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| WMImplant | Sysmon Configuration | [T0000\_wmimplant.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T0000_wmimplant.xml)


## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Situational Awareness |  parent\_process\_name = "wmiprvse.exe" AND pipe\_name = "Anonymous Pipes" WHERE event\_id = "17" OR event\_id = "18" AND count = "=>2" | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/process.md)| 



## Hunter Notes
* Wmiprvse.exe as a ParentImage and PowerShell as an Image is most likely WMI via powershell (Take in consideration that powershell can be renamed so focus on the context around the process)
* ParentCommandile or CommandLine with the strings provided above is a clear indicator of basic/default WMImplant obfuscation
* Environment registry keys created with a 5 Character random alphanumeric name by wmiprvse.exe
* Values with strings 'Win32_OSRecoveryConfiguration' or 'DebugFilePath' set to the weird keys created by wmiprvse.exe
* 2 \<Anonymous Pipes\> when WMImplant executes commands remotely to a compromised box.
* Remember this is considering the default execution of the tool. Adversaries could change the number of characters in the Environment Variable and avoid using the ObfuscatedEnvVar parameter. If this happens, you could stack the values of the Enviroment variables and if variables are not used, you could baseline the use of WMI executing PowerShell in your organization.


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
