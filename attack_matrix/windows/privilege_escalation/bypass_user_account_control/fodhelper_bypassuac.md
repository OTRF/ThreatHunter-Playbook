# Fodhelper BypassUAC
## Technique ID
T1088_foodhelper


## Description
Fodhelper.exe was introduced in Windows 10 to manage optional features like region-specific keyboard settings. It’s location is: C:\Windows\System32\fodhelper.exe and it is signed by Microsoft. This program is allowed to elevate itself to run in a high integrity context automatically. There is no need for any user interaction to allow the process to elevate. This means that if we are able to tamper the behavior of the binary to load a file of our choice, this file may start in a high integrity context, too

Fodhelper.exe looks for the following Reg Keys first:
* “HKCU:\Software\Classes\ms-settings\shell\open\command”
* “HKCU:\Software\Classes\ms-settings\shell\open\command\DelegateExecute” 

Once it finds the last value (DelegateExecute), it executed the contents of the following key:
* “shell\open\command\(default)” 


## Hypothesis
Adversaries might be leveraging Fodhelper.exe to bypass UAC and elevate privileges within my network.


## Events

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 1 | ParentImage | fodhelper.exe OR (powershell.exe OR cmd.exe) | [Winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) |
| Sysmon | 1 | Image | fodhelper.exe OR (powershell.exe OR cmd.exe) | [Winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) |
| Sysmon | 1 | CommandLine | Suspicious strings or Images(\<base64\>, powershell.exe, cmd.exe, etc.) | [Winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) |
| Sysmon | 12 | TargetObject | '\ms-settings\shell\open\command' | [Winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) |
| Sysmon | 12 | EventType | CreateKey OR DeleteKey | [Winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) |
| Sysmon | 13 | TargetObject | '\ms-settings\shell\open\command\DelegateExecute' |[Winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) |
| Sysmon | 13 | Details | '(Empty)' |[Winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) |
| Sysmon | 13 | TargetObject | '\ms-settings\shell\open\command\(Default)' |[Winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) |
| Sysmon | 13 | Details | Suspicious Strings or images (<base64>, powershell.exe, cmd.exe, etc.) |[Winscripting](https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/) |


# Atomic Sysmon Configuration
[T1088_foodhelper.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T1088_foodhelper.xml)


## Hunter Notes
* Look for suspicious images such as powershell, cmd, rundll32, etc spawning eventvwr.exe and vice-versa.
  * Remember that the processes specified above would catch the most common scenarios. Advanced adversaries can rename processes or use other processes to execute commands.
* You can also hunt for base64 or other suspicious images/modules being executed as part of command line events with fodhelper.exe as a parent.
* You can also stack the values of '\ms-settings\shell\open\command\DelegateExecute' OR '\ms-settings\shell\open\command\(Default)' if it is common/normal behavior in your environment. That could be a good way to start looking for this behavior.
* If this is something that you know does not happen in your environment, then you could automate the detection of this behavior.


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
