# Malicious Office Documents
## Description
Malicious Office documents often leverage macros to launch commands via cmd.exe or PowerShell. In other cases, Office documents might include script content embedded as an object. When a user double clicks that object, Office will write the script to the %TEMP% folder and execute it using wscript.exe or cscript.exe. Both cases require user interaction, but still represent a common delivery mechanism for additional malware.

## Hypothesis
Adversaries are likely leveraging malicious Office documents to deliver malware within the environment

## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | ParentImage | office | Cyb3rWard0g & [MalwareSoup](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/) |
| Sysmon | 1 | Image | cmd.exe | Cyb3rWard0g & [MalwareSoup](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/) |
| Sysmon | 1 | Image | wscript.exe | Cyb3rWard0g & [MalwareSoup](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/) |
| Sysmon | 1 | Image | cscript.exe | Cyb3rWard0g & [MalwareSoup](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/) |
| Sysmon | 1 | CommandLine | powershell | Cyb3rWard0g & [MalwareSoup](https://malwaresoup.com/detecting-some-malicious-office-documents-using-sysmon/) |


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
