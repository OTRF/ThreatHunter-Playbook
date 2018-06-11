# DLL Injection via LoadLibrary API Call
## Technique ID
T1055\_LoadLibrary


## Description
Microsoft Windows allows for processes to remotely create threads within other processes of the same privilege level. This functionality is provided via the Windows API CreateRemoteThread. Both adversaries and host-based security software use this functionality to inject DLLs, but for very different purposes. An adversary is likely to inject into a program to evade defenses or bypass User Account Control, but a security program might do this to gain increased monitoring of API calls. 

One of the most common methods of DLL Injection is through the Windows API LoadLibrary.
* Allocate memory in the target program with VirtualAllocEx
* Write the name of the DLL to inject into this program with WriteProcessMemory
* Create a new thread and set its entry point to LoadLibrary using the API CreateRemoteThread.

This behavior can be detected by looking for thread creations across processes, and resolving the entry point to determine the function name. If the function is LoadLibraryA or LoadLibraryW, then the intent of the remote thread is clearly to inject a DLL. When this is the case, the source process must be examined so that it can be ignored when it is both expected and a trusted process.


## Hypothesis
Adversaries are moving laterally within my network through remote PowerShell sessions. 

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| \[TBD\](TBD)| TBD | \[TBD\](TBD) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring| Sysmon|




## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 8 | StartFunction | "LoadLibraryA" OR "LoadLibraryW" | [MITRE CAR](https://car.mitre.org/wiki/CAR-2013-10-002) |


## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| LoadLibrary | Sysmon Configuration |[T1055\_LoadLibrary.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T1055_LoadLibrary.xml)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Situational Awareness | event WHERE event_id == "8"   | [TBD]\(TBD)| 


## Hunter Notes
* Searching for that specific event reduces the numbe of false positives when using the Windows API CreateRemoteThreat.
* If there is any security software that legitimately injects DLLs, it must be carefully whitelisted.


## Hunting Techniques Recommended

- [ ] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
