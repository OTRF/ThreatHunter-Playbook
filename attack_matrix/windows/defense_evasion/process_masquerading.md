# Process Masquerading
## Technique ID
T1036


## Description
Masquerading occurs when the name or location of an executable, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. Several different variations of this technique have been observed.

One variant is for an executable to be placed in a commonly trusted directory or given the name of a legitimate, trusted program. Alternatively, the filename given may be a close approximation of legitimate programs. This is done to bypass tools that trust executables by relying on file name or path, as well as to deceive defenders and system administrators into thinking a file is benign by associating the name with something that is thought to be legitimate. Source: [T1036_Masquerading](https://attack.mitre.org/wiki/Technique/T1036)

## Hypothesis
Adversaries might be evading detection by "blending" into the environment by mimicking standard processes. 

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| \[TBD](TBD)| TBD | \[TBD\](TBD) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring| Sysmon|
|Process Monitoring| WinEvent| 

## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | Image, ParentImage, SID, CurrentDirectory, CommandLine, ParentCommandLine | Started with wrong parent process, Image is located in the wrong path, Misspelled process, Running under an incorrect SID, Unusual command-line arguments | [SANS "Find Evil"](https://digital-forensics.sans.org/media/poster_2014_find_evil.pdf) |
|WinEvent|4688|Security ID, Account Name, New Process ID, New Process Name, Token Elevation Type, Mandatory Label (Win10), Creator Process ID, Creator Process Name (Win10), Process Command Line|Started with wrong creator process, Image is located in the wrong path, Misspelled process, Running under an incorrect SID, Unusual command-line arguments|[SANS "Find Evil"](https://digital-forensics.sans.org/media/poster_2014_find_evil.pdf)| 

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
|N/A | N/A | [N/A\](N/A)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier |  process\_parent\_name = "\*" OR process\_command\_line = "\*" WHERE process\_name = "*" | [process](https://github.com/bfuzzy/OSSEM/blob/master/detection_data_model/data_objects/process.md) | 


## Hunter Notes
* Baseline processes common to your environment
* Process counts and odd start times should be looked at
* Narrowing the data could be difficult suggest starting with native Windows processes first


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
