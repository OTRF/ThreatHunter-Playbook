# Create Remote Process via WMIC
## Technique ID
T1028\_wmic\_remote


## Description
wmic.exe is a powerful command line utility for interacting with WMI. It has a large amount of convenient default aliases for WMI objects but you can also perform more complicated queries. wmic.exe can also execute WMI methods and is used often by attackers to perform lateral movement by
calling the Win32_ProcessCreate method.[Source](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf)


## Hypothesis
Adversaries might be using wmic leveraging stolen credentials to perform lateral movement within my environment to create/run a process on a remote host. 

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [WMIC Process Call Create](https://github.com/redcanaryco/atomic-red-team/blob/20a447e63de9d5ef836534743c6f8fdef16c5874/atomics/T1028/T1028.md#atomic-test-3---wmic-process-call-create)| Utilize WMIC to start remote process | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/20a447e63de9d5ef836534743c6f8fdef16c5874/atomics/T1028/T1028.md#atomic-test-3---wmic-process-call-create) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring| Sysmon |
|Process Monitoring| WinEvent| 
|Process command-line parameters|Sysmon |
|Authentication logs| WinEvent | 


## Specific Events

### Source Host
| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4688 | NewProcessName | 'wmic' | [MITRE](https://car.mitre.org/wiki/CAR-2016-03-002), [JPCERT](https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf) |
| WinEvent | 4688 | ProcessCommandLine | "* process call create *" AND "* /node:*" | [MITRE](https://car.mitre.org/wiki/CAR-2016-03-002) |
| Sysmon | 1 | Image | 'wmic' | [JPCERT](https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf) |
| Sysmon | 1 | CommandLine |  "* process call create *" AND "* /node:*" | [MITRE](https://car.mitre.org/wiki/CAR-2016-03-002) |
| WinEvent | 4674 | ProcessName | 'wmic' | Cyb3rWard0g |
| WinEvent | 4674 | ObjectName | '\ControlSet001\services\WinSock2\Parameters' | Cyb3rWard0g |
| Sysmon | 12 | EventType | 'Createkey' | Cyb3rWard0g |
| Sysmon | 12 | Image | 'wmic' | Cyb3rWard0g |
| Sysmon | 12 | Image | '\CurrentControlSet\services\Tcpip\Parameters' | Cyb3rWard0g |
| WinEvent | 4648 | SubjectAccountName & TargetUserName | Different user accounts | Cyb3rWard0g |
| Sysmon | 3 | DestinationIP & Destination Hostname | Internal Hosts | Cyb3rWard0g |
| Sysmon | 3 | DestinationPort | 135 | Cyb3rWard0g |


### Destination Host
| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4672 | SubjectAccountName | NOT Local username | Cyb3rWard0g |
| WinEvent | 4624 | TargetUsername | NOT Local username | Cyb3rWard0g |
| WinEvent | 4624 | SourceNetworkAddress | NOT Local IP OR Internal IPs | Cyb3rWard0g |
| Sysmon | 1 | ParentImage | 'wmiprvse.exe' | Cyb3rWard0g, [JPCERT](https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf) |
| Sysmon | 1 | ParentCommandLine | 'C:\Windows\System32\wbem\wmiprvse.exe -secured -Embbeding' | Cyb3rWard0g, [JPCERT](https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf) |
| Sysmon | 1 | User | NOT Local user | Cyb3rWard0g, [JPCERT](https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| wmic remote | Sysmon configuration | [T0000\_wmic\_remote.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T0000_wmic_remote.xml)


## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
|  Situational Awareness | process WHERE parent\_process\_name == "*" AND user_name NOT "local user"| [process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/process.md)| 


## Hunter Notes
* When hunting for this specific technique across all your endpoints, make sure you remember what happens where (Source or Destination)
* On both locations, filter (localhost or ::1) on DestinationIPs fields to spot computers talking to each other within your environment
* Filter out local accounts in order to catch new or explicit credentials being used to execute/create processes
  * On the destination host, look for processes being executed by a different user and stack the values
* On the destination host, look for WmiPrvse.exe as a parent. You will be surprised how this is not a usual event
* On the source host, stack proces names talking to internal systems on DestinationPort 135. 


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
