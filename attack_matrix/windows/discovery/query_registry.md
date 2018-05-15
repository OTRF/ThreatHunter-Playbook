# Query Registry
## Technique ID
T1012


## Description
Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.

The Registry contains a significant amount of information about the operating system, configuration, software, and security. Some of the information may help adversaries to further their operation within a network.

Source: [T1012_Query\_Registry](https://attack.mitre.org/wiki/Technique/T1012)

## Hypothesis
An attacker could query the registry to dertmine  privilege escalation and persistance opportunities.

## Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
|Sysmon | 1 | Image| C:\Windows\System32\reg.exe | - |
|Sysmon | 1 | CommandLine| *query, *save, *add, *export, *import  | - |
|WinEvent | 4688 | ProcessCommandLine | *query, *save, *add, *export, *import | - |
|WinEvent | 4688 | NewProcessName | C:\Windows\System32\reg.exe | - |


 



## Atomic Sysmon Configuration

None


## Hunter Notes
* Look at commonly abused Registry keys 
* Filter out known good
* Look for odd parent processes that are spawning *reg.exe
* Does not include other known ways to query the regitry through the Windows API 


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
