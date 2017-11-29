# Bitsadmin
## Technique ID
T0000_bitsadmin


## Description
BITSAdmin is a command-line tool that you can use to create download or upload jobs and monitor their progress.The BITSAdmin tool uses switches to identify the work to perform. Most switches require a Job parameter that you set to the job's display name or GUID. Note that a job's display name may not be unique. The /create and /list switches return a job's GUID [Source](https://msdn.microsoft.com/en-us/library/windows/desktop/aa362813(v=vs.85).aspx). Adversaries can take advantage of Bitsadmin's switch "/Transfer" to create a download job (Download a file).


## Hypothesis
Adversaries might be leveraging Bitsadmin.exe to download files on compromised systems within my environment.


## Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 4688 | NewProcessName | bitsadmin.exe | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/Bitsadmin.md) |
| WinEvent | 4688 | ProcessCommandLine | bitsadmin.exe AND (/transfer OR (/transfer AND /Download)) | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/Bitsadmin.md) |
| WinEvent | 1 | Image OR ParentImage | bitsadmin.exe | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/Bitsadmin.md) |
| WinEvent | 1 | CommandLine OR ParentCommandLine | bitsadmin.exe AND (/transfer OR (/transfer AND /Download)) | [RedCanary-AtomicRedTeam](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/Bitsadmin.md) |


## Atomic Sysmon Configuration
[T0000_bitsadmin.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T0000_bitsadmin.xml)


## Hunter Notes
* You could simply look for the use of bitsadmin via Sysmon or native Windows event logs correlating process name bitsadmin with command argument "/Transfer". You could also add the command argument "/download", but it is optional since "/transfer" by itself creates a download job by default. 
* Stacking also the values of child processes spawned by bitsadmin could be interesting.

## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests