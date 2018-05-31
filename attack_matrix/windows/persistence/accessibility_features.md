# Accessibility Features
## Technique ID
T1015


## Description
Windows contains accessibility features that may be launched with a key combination before a user has logged in (for example, when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.

Two common accessibility programs are C:\Windows\System32\sethc.exe, launched when the shift key is pressed five times and C:\Windows\System32\utilman.exe, launched when the Windows + U key combination is pressed. The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen.[MITRE](https://attack.mitre.org/wiki/Technique/T1015).


## Hypothesis
Adversaries might be using accessibility feature applications in order to maintain persistence and elevate privileges in my environment


## Attack Simulation

| Script  | Short Description | Author | 
|---------|---------|---------|
| [Command Prompt As Debugger To Process](https://github.com/redcanaryco/atomic-red-team/blob/fe76e96d4b4dfe72731306278b36a46f61b5aa20/atomics/T1015/T1015.md#atomic-test-1---attaches-command-prompt-as-debugger-to-process)| Allows adversaries to execute the attached process| [atomic-red-team](https://github.com/redcanaryco/atomic-red-team/blob/fe76e96d4b4dfe72731306278b36a46f61b5aa20/atomics/T1015/T1015.md#atomic-test-1---attaches-command-prompt-as-debugger-to-process) |



## Recommended Data Sources

| ATT&CK Data Source | Event Log |
|---------|---------|
|Process Monitoring| Sysmon |
|Process Monitoring|WinEvent| 
|Registry Monitoring|Sysmon |




## Specific Events


| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1 | ParentImage | sethc.exe, utilman.exe, osk.exe, Magnify.exe, Narrator.exe, DisplaySwitch.exe, AtBroker.exe | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| Sysmon | 12, 13 | TargetObject | 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' AND 'Debugger' | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |
| WinEvent | 4688 | ParentProcessName | sethc.exe, utilman.exe, osk.exe, Magnify.exe, Narrator.exe, DisplaySwitch.exe, AtBroker.exe | [Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| accessibility features| Sysmon configuration | [T1015\_accessibility\_features.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T1015_accessibility_features.xml)



## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Behavioral Analytics |  (parent\_process\_name = "setchc.exe" OR parent\_process\_name = "osk.exe" OR parent\_process\_name = "utilman.exe" OR parent\_process\_name = "Magnify.exe" OR parent\_process\_name = "DisplaySwitch.exe" OR parent\_process\_name = "AtBroker.exe") OR (process\_name = "setchc.exe" OR process\_name = "osk.exe" OR process\_name = "utilman.exe" OR process\_name = "Magnify.exe" OR process\_name = "DisplaySwitch.exe" OR process\_name = "AtBroker.exe") AND target_object CONTAINS ('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' AND 'Debugger')  | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/master/detection_data_model/data_objects/process.md), [registry]\(TBD\) | 




## Hunter Notes
* Pretty straighforward query to find the specific accessibility feature applications that allow this technique and its values. This could be automated and converted into a high fidelity rule with the right context


## Hunting Techniques Recommended

- [ ] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
