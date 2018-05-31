# Malicious Office Documents
## Technique ID
T0000\_office\_process\_creation


## Description
Malicious Office documents often leverage macros to launch commands via cmd.exe or PowerShell. In other cases, Office documents might include script content embedded as an object. When a user double clicks that object, Office will write the script to the %TEMP% folder and execute it using wscript.exe or cscript.exe. Both cases require user interaction, but still represent a common delivery mechanism for additional malware.


## Hypothesis
Adversaries are likely leveraging malicious Office documents to deliver malware within the environment

## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [Malicious Macro Generator](https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator)| Creates Office Macros to execute code via Office documents | [Mr-Un1k0d3r](https://github.com/Mr-Un1k0d3r) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
| Process Monitoring| Sysmon |


## Specific Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | ParentImage | office | Cyb3rWard0g & [MalwareSoup](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/) |
| Sysmon | 1 | Image | cmd.exe | Cyb3rWard0g & [MalwareSoup](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/) |
| Sysmon | 1 | Image | wscript.exe | Cyb3rWard0g & [MalwareSoup](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/) |
| Sysmon | 1 | Image | cscript.exe | Cyb3rWard0g & [MalwareSoup](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/) |
| Sysmon | 1 | CommandLine | powershell | Cyb3rWard0g & [MalwareSoup](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Office process creation | Sysmon Configuration | [T0000\_office\_process\_creation.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T0000_office_process_creation.xml)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier |  process\_parent\_name = "winword.exe" OR process\_parent\_name = "excel.exe" OR  process\_parent\_name = "powerpnt.exe" WHERE process\_name = "*" | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/process.md) | 



## Hunter Notes
* Detects most common scenarios using these techniques. More creative attackers will likely be able to conceal activity (using different binaries, renaming binaries, etc) and potentially bypass these detections.
* Look for any Office application creating processes for cmd.exe, wscript.exe, or cscript.exe
* Also search the CommandLine field for any occurence of the string powershell
* Reference: [Detecting (Some) Malicious Office Documents Using Sysmon](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/)


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
