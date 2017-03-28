# WMImplant Command_Exec
## Description
A PowerShell based tool that leverages WMI to both perform actions against targeted machines, but also as the C2 channel for issuing commands and receiving results. The **command_exec** command is part of the **Lateral Movement Facilitation Commands** section which allows an adversary to run command lines remotely with compromised credentials.


## Hypotheis
Adversaries might be executing WMImplant in my environment in order to facilitate lateral movement by running commands remotely with compromised credentials.


## Events

| Source | EventID | Event Name        | Values                                                                                                                 | Author      | References            |
|--------|---------|-------------------|------------------------------------------------------------------------------------------------------------------------|-------------|-----------------------|
| Sysmon | 1       | ParentImage       | powershell.exe                                                                                                         | Cyb3rWard0g | https://goo.gl/Z9aTUK |
| Sysmon | 1       | ParentCommandLine | 'Get-C\`hildItem', 'Get-C\`ommand', 'DI\`R', 'L\`S', 'Child\`Item', 'Inv\`oke-Ex\`pression', 'IE\`X', 'G\`CI', env:, 'Co\`mmand' | Cyb3rWard0g | https://goo.gl/Z9aTUK |
| Sysmon | 12, 13  | TargetObject      | Pattern: \\Environment\\[a-zA-Z0-9]{5}                                                                                 | Cyb3rWard0g | https://goo.gl/Z9aTUK |
| Sysmon | 13 | Details          | 'Win32_OSRecoveryConfiguration', 'DebugFilePath'                                                                                                      | Cyb3rWard0g | https://goo.gl/Z9aTUK |
| Sysmon | 17, 18 | PipeName          | \<Anonymous Pipes\>                                                                                                      | Cyb3rWard0g | https://goo.gl/Z9aTUK |


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
