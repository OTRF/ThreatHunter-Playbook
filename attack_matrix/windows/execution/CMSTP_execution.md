# CMSTP
## Technique ID
T1191


## Description
The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections.

Adversaries may supply CMSTP.exe with INF files infected with malicious commands. Similar to Regsvr32 / ”Squiblydoo”, CMSTP.exe may be abused to load and execute DLLs and/or COM scriptlets (SCT) from remote servers. This execution may also bypass AppLocker and other whitelisting defenses since CMSTP.exe is a legitimate, signed Microsoft application.

CMSTP.exe can also be abused to Bypass User Account Control and execute arbitrary commands from a malicious INF through an auto-elevated COM interface. Source: [T1191_CMSTP](https://attack.mitre.org/wiki/Technique/T1191)

## Hypothesis
Use process monitoring to detect and analyze the execution and arguments of CMSTP.exe

## Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | Image | cmstp.exe | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/CMSTP.md) | 
|Sysmon | 1 | CommandLine | /s OR /ni /s | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/CMSTP.md) |
|WinEvent | 4688 | NewProcessName| cmstp.exe | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/CMSTP.md) |
|WinEvent | 4688 | ProcessCommandLine | /s OR /ni /s | [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/CMSTP.md) |

 



## Atomic Sysmon Configuration

None


## Hunter Notes
* Baseline CMSTP.exe usage in the environment include arguments during execution and loaded files


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
