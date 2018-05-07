# Adversary Technique
## Technique ID
T1036_Masquerading


## Description
Masquerading occurs when the name or location of an executable, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. Several different variations of this technique have been observed.

One variant is for an executable to be placed in a commonly trusted directory or given the name of a legitimate, trusted program. Alternatively, the filename given may be a close approximation of legitimate programs. This is done to bypass tools that trust executables by relying on file name or path, as well as to deceive defenders and system administrators into thinking a file is benign by associating the name with something that is thought to be legitimate. Source: [T1036_Masquerading](https://attack.mitre.org/wiki/Technique/T1036)

## Hypothesis
Adversaries might be evading detection by "blending" into the environment by mimicking standard processes. 

## Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | Image, ParentImage, SID, CurrentDirectory, CommandLine, ParentCommandLine | Started with wrong parent process, Image is located in the wrong path, Misspelled process, Running under an incorrect SID, Unusual command-line arguments | [SANS "Find Evil"](https://digital-forensics.sans.org/media/poster_2014_find_evil.pdf) |



## Atomic Sysmon Configuration

None


## Hunter Notes
* Baseline processes common to your environment
* Process counts and odd start times should be looked at
* Narrowing the data could be difficult suggest starting with native Windows processes first


## Hunting Techniques Recommended

- [ ] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
