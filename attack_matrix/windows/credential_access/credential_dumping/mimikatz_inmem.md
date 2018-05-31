# In-Memory Mimikatz
## Technique ID
T1003

## Description
Technique of reflectively loading Mimikatz into Memory. Mainly used to dump credentials without touching disk.

Mimikatz Command: 
* sekurlsa::LogonPasswords : lists all available provider credentials. This usually shows recently logged on user and computer credentials.

Monitoring OpenProcess() : [dim0x69 - blog.3or.de](https://blog.3or.de/hunting-mimikatz-with-sysmon-monitoring-openprocess.html)

| module | OpenProcess caller function | destination process / destination service | ACCESS\_MASK | ACCESS\_MASK translated | comment |
|---------|---------|---------|---------|---------|---------|
| sekurlsa::* | kuhl\_m\_sekurlsa\_acquireLSA() | lsass.exe | PROCESS\_VM\_READ \| PROCESS\_QUERY\_INFORMATION | 0x1410 | for Windows Version < 5 |
| sekurlsa::* | kuhl\_m\_sekurlsa\_acquireLSA() | lsass.exe | PROCESS\_VM\_READ \| PROCESS\_QUERY\_LIMITED\_INFORMATION | 0x1010 | for Windows Version >= 6 |


## Hypothesis
Adversaries might be executing Mimikatz in memory with the help of PowerShell in order to dump credentials in my environment.


## Attack Simulation


| Script  | Short Description | Author | 
|---------|---------|---------|
| [mimikatz](https://github.com/gentilkiwi/mimikatz)| Credential dumper | [Benjamin Delpy](http://blog.gentilkiwi.com/) |


## Recommended Data Sources

| ATT&CK Data Source | Event Log | Description |
|---------|---------|---------|
|Process Monitoring| Sysmon | Process access | 
|Process Monitoring| Sysmon | Image Loaded
|PowerShell Logs| PowerShell | Module Logging |
|PowerShell Logs| PowerShell | Script-Block Logging |
|Sensitive Privilege Use| Windows Security Auditing |Audit Sensitive Privilege Use |

## Specific Events

| Source | EventID | EventFields | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 10 | GrantedAccess | 0x1010, 0x1410 | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | GrantedAccess | 0x1438, 0x143a, 1418 | [dim0x69 - blog.3or.de](https://blog.3or.de/hunting-mimikatz-with-sysmon-monitoring-openprocess.html) |
| Sysmon | 10 | SourceImage | powershell.exe OR ANY | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | TargetImage | lsass.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | CallTrace | \\\ntdll\\.dll\\+\[a-zA-Z0-9\]\{1,\}\|\\\KERNELBASE\\.dll\\+\[a-zA-Z0-9\]\{1,\}\|UNKNOWN\(\[a-zA-Z0-9\]\{16\}\) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 7 | ImageLoaded | WinSCard.dll, cryptdll.dll, hid.dll, samlib.dll, vaultcli.dll, WMINet_Utils.dll (Optional) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Mimikatz | Sysmon configuration | [T1003\_mimikatz\_inmem.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T1003_mimikatzinmem.xml)
|  Audit Sensitive Privilege Use | You will need to enable an Audit Policy of Privilege Use Category -> Sub-category Audit Sensitive Privilege Use | [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4673#security-monitoring-recommendations) |


## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier | target\_process\_name = "lsass.exe" AND process\_granted\_access = "*" COUNT BY process\_name  | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/c0bf44fb8c527f6e678c4ff1321814108e024315/detection_data_model/data_objects/process.md) |



## Hunter Notes
* GrantedAccess code 0x1010 is the new permission Mimikatz v.20170327 uses for command "sekurlsa::logonpasswords"
  * 0x00000010 = VMRead
  * 0x00001000 = QueryLimitedInfo
* GrantedAccess code 0x1010 is less common than 0x1410
* Out of all the Modules that Mimikatz needs to function, the 5 above are the ones with less false positives
* WMINet_Utils.dll is optional since it is loaded by scripts developed by PowerSploit and Empire projects (Invoke-Mimikatz.ps1).
* Look for PowerShell.exe (Suspicious) or other processes accessing Lsass.exe with a potential CallTrace Pattern: C:\\Windows\\SYSTEM32\\ntdll\.dll\+[a-zA-Z0-9]{1,}\|C:\\Windows\\system32\\KERNELBASE\.dll\+[a-zA-Z0-9]{1,}\|UNKNOWN\([a-zA-Z0-9]{16}\)
	* Remember that an attacker can easily run Mimikatz or other credential dumping tool under a different process. This hypothesis is focusing on PowerShell as a process hosting the script. However, you can change this hypothesis to look for other Microsoft signed binaries or any process in the system. The idea is to focus on the patterns of behavior.
* The values for the GrantedAccess field in Sysmon EID 10 besides 0x1010 & 0x140 are other permissions needed for several of the modules used by Mimikatz. The following table lists most of the calls to OpenProcess() with the opened service / process name and the associated ACCESS_MASK.

| module | OpenProcess caller function | destination process / destination service | ACCESS\_MASK | ACCESS_MASK translated | comment |
|---------|---------|---------|---------|---------|---------|
| lsadump::lsa /patch | kuhl\_m\_lsadump\_lsa\_getHandle() | SamSs | PROCESS\_VM\_READ \| PROCESS\_VM_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 |
| lsadump::lsa /inject | kuhl\_m\_lsadump\_lsa\_getHandle() | SamSs | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE  \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION \| PROCESS\_CREATE\_THREAD | 0x143a |
| lsadump::trust /patch | kuhl_m_lsadump_lsa_getHandle() | SamSs | PROCESS_VM_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION| 0x1438 |
| minesweeper::infos | kuhl\_m\_minesweeper\_infos() | minesweeper.exe | PROCESS\_VM\_READ \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1418 |
| misc:detours | kuhl\_m\_misc\_detours\_callback\_process() | * |GENERIC\_READ | |omitted because of the very generic ACCESS_MASK |
| misc:memssp |  kuhl\_m\_misc\_memssp() | lsass.exe | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 |
| process::suspend, process:stop, process:resume,process:imports, process:exports |kuhl\_m\_process\_genericOperation()|||| omitted because of the very generic ACCESS_MASKs|
| vault::cred /patch|  kuhl\_m\_vault\_cred() | SamSs | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 | |
| token::list, token::elevate, token::run | querying all processes on the system |*||first 0x1400 then 0x40| all three commands result in a call to kull\_m\_token\_getTokens() which first iterates over **all** processes and threads with OpenProcess(PROCESS\_QUERY\_INFORMATION (0x1400)) (kull\_m\_token\_getTokens\_process\_callback()) and then again to get the tokens OpenProcess(PROCESS\_DUP\_HANDLE (0x40)) (in kull\_m\_handle\_getHandlesOfType_callback()) to duplicate the Tokens. This results in many thousand (!) Events with ID 10 (!)|
| crypto::cng | kull\_m\_patch\_genericProcessOrServiceFromBuild() via  kuhl\_m\_crypto\_p\_cng() |KeyIso | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 | |
| event::drop | kull\_m\_patch\_genericProcessOrServiceFromBuild() via  kuhl\_m\_event\_drop() | EventLog | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 | ** this event does not get logged! :O mimikatz seems to be fast enough to apply the patch before the event gets logged!**|
| misc::ncroutemon | kull\_m\_patch\_genericProcessOrServiceFromBuild() via  kuhl\_m\_misc\_ncroutemon() | dsNcService| PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 | |
| ts::multirdp| kull\_m\_patch\_genericProcessOrServiceFromBuild() via  kuhl\_m\_ts\_multirdp() | TermService | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 | 

* You could use a stack counting technique to stack all the values of the permissions invoked by processes accessing Lsass.exe. You will have to do some filtering to reduce the number of false positives. You could then group the results with other events such as modules being loaded (EID 7). A time window of 1-2 seconds could help to get to a reasonable number of events for analysis.


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forest
