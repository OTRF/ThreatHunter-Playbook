# Bypassing Application Whitelisting with Regsvr32.exe
## Description
Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft.

Adversaries can use Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Both utilities may be used to bypass process whitelisting through use of attributes within the binary to specify code that should be run before registration or unregistration: [ComRegisterFunction] or [ComUnregisterFunction] respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute [Source](https://attack.mitre.org/wiki/Technique/T1121#scite-231f6587c883d0c99b56e5a752f7dea1)

## Hypothesis
Adversaries might be bypassing our application whitelisting controls by using Regsvcs and Regasm in order to execute malicious binaries or scripts within my environment.


## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4688 | NewProcessName | *regsvcs.exe OR *regasm.exe | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/RegsvcsRegasm.md) |
| WinEvent | 1 | Image OR ParentImage | *regsvcs.exe OR *regasm.exe | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/RegsvcsRegasm.md) |


## Hunter Notes
* If those two binaries are commonly used in your environment then stacking is a good technique to find outliers. The key is to return a managable number of results to keep digging.
* When looking for regasm.exe, look for "/U" in the command arguments since it is used to create classes found in the assemly file (suspicious/malicious binary).
* Stacking also the values of child processes spawned by regsvcs or regasm could be interesting.

## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [X] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests