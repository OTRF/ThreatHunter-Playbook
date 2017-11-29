# Remote Dir $ Share Enumeration
## Technique ID
T1135


## Description
Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.


## Hypothesis
Adversaries are enumerating remote file shares within my environment.


## Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| WinEvent | 5145 | ShareName | *c$ OR *ADMIN$ | [Jack Crook](https://t.co/HSykx8LC6V) |
| WinEvent | 5145 | AccessMask | 0x100080 | [Jack Crook](https://t.co/HSykx8LC6V) |
| WinEvent | 5145 | SourceAddress/IPAddress | NOT 127.0.0.1 | [Jack Crook](https://t.co/HSykx8LC6V) |


## Atomic Sysmon Configuration
None


## Hunter Notes
* Bucket 3 events within 1 sec by ComputerName


## Hunting Techniques Recommended

- [x] Grouping
- [ ] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
