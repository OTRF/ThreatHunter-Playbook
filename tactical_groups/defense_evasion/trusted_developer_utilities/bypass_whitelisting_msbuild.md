# Msbuild
## Description
MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It takes XML formatted project files that define requirements for building various platforms and configurations.
Adversaries can use MSBuild to proxy execution of code through a trusted Windows utility. The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into the XML project file. MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application whitelisting defenses that are configured to allow MSBuild.exe execution[Source](https://attack.mitre.org/wiki/Technique/T1127).


## Hypothesis
Adversaries might be bypassing our application whitelisting controls by using msbuild in order to execute malicious binaries or scripts within my environment.


## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4688 | NewProcessName | msbuild.exe | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/Trusted_Developer_Utilities.md) |
| Sysmon | 1 | Image OR ParentImage | msbuild.exe | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/Trusted_Developer_Utilities.md) |


## Hunter Notes
* If msbuild is commonly used in your environment then stacking is a good technique to find outliers. The key is to return a managable number of results to keep digging.
* Stacking also the values of child processes spawned by msbuild could be interesting.  


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests