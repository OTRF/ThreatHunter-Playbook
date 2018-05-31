# Query Registry
## Technique ID
T1012


## Description
Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.

The Registry contains a significant amount of information about the operating system, configuration, software, and security. Some of the information may help adversaries to further their operation within a network.

Source: [T1012\_Query\_Registry](https://attack.mitre.org/wiki/Technique/T1012)

## Hypothesis
An attacker could query the registry to dertmine  privilege escalation and persistance opportunities.

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [Query Registry](https://github.com/redcanaryco/atomic-red-team/blob/2c6de1a62031db286f72795c5dcb256217edb7bb/atomics/T1012/T1012.md#atomic-test-1---query-registry)| Uses Reg to interact with the Windows Registry | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/2c6de1a62031db286f72795c5dcb256217edb7bb/atomics/T1012/T1012.md#atomic-test-1---query-registry) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring| Sysmon|
|Process Monitoring|WinEvent| 

## Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
|Sysmon | 1 | Image| C:\Windows\System32\reg.exe | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/2c6de1a62031db286f72795c5dcb256217edb7bb/atomics/T1012/T1012.md) |
|Sysmon | 1 | CommandLine| *query, *save, *add, *export, *import  | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/2c6de1a62031db286f72795c5dcb256217edb7bb/atomics/T1012/T1012.md) |
|WinEvent | 4688 | ProcessCommandLine | *query, *save, *add, *export, *import | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/2c6de1a62031db286f72795c5dcb256217edb7bb/atomics/T1012/T1012.md)|
|WinEvent | 4688 | NewProcessName | C:\Windows\System32\reg.exe | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/2c6de1a62031db286f72795c5dcb256217edb7bb/atomics/T1012/T1012.md) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| N/A | N/A | \[N/A\](N/A)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Situational Awareness |  process\_parent\_name = "reg.exe" AND process_command_line = "*"  | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/process.md) | 


## Hunter Notes
* Look at commonly abused Registry keys 
* Filter out known good
* Look for odd parent processes that are spawning *reg.exe
* Does not include other known ways to query the registry through the Windows API 


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
