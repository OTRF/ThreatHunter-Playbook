# In-Memory Mimikatz
## Description
Technique of reflectively loading Mimikatz into Memory. Mainly used to dump credentials without touching disk.


## Hypothesis
Adversaries might be executing Mimikatz in memory with the help of PowerShell in order to dump credentials in my environment.


## Events

| Source | EventID | Fields | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 10 | GrantedAccess | 0x1010, 0x1410 | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | GrantedAccess | 0x1438, 0x143a, 1418 | [dim0x69 - blog.3or.de](https://blog.3or.de/hunting-mimikatz-with-sysmon-monitoring-openprocess.html) |
| Sysmon | 10 | SourceImage | powershell.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | TargetImage | lsass.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | CallTrace | \\\ntdll\\.dll\\+\[a-zA-Z0-9\]\{1,\}\|\\\KERNELBASE\\.dll\\+\[a-zA-Z0-9\]\{1,\}\|UNKNOWN\(\[a-zA-Z0-9\]\{16\}\) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 7 | ImageLoaded | WinSCard.dll, cryptdll.dll, hid.dll, samlib.dll, vaultcli.dll, WMINet_Utils.dll (Optional) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html) |


## Hunter Notes
* GrantedAccess code 0x1010 is the new permission Mimikatz v.20170327 uses for command "sekurlsa::logonpasswords"
  * 0x00000010 = VMRead
  * 0x00001000 = QueryLimitedInfo
* GrantedAccess code 0x1010 is less common than 0x1410
* Out of all the Modules that Mimikatz needs to function, the 5 above are the ones with less false positives
* WMINet_Utils.dll is optional since it is loaded by scripts developed by PowerSploit and Empire projects (Invoke-Mimikatz.ps1).
* Look for PowerShell.exe accessing Lsass.exe with a potential CallTrace Pattern: C:\\Windows\\SYSTEM32\\ntdll\.dll\+[a-zA-Z0-9]{1,}\|C:\\Windows\\system32\\KERNELBASE\.dll\+[a-zA-Z0-9]{1,}\|UNKNOWN\([a-zA-Z0-9]{16}\)
	* Remember that an attacker can easily run Mimikatz or other credential dumping tool under a different process. This hypothesis is focusing on PowerShell as a process hosting the script. However, you can change this hypothesis to look for other Microsoft signed binaries or any process in the system. The idea is to focus on the patterns of behavior.
* The values for the GrantedAccess field in Sysmon EID 10 besides 0x1010 & 0x140 are other permissions needed for several of the modules used by Mimikatz. The following table lists most of the calls to OpenProcess() with the opened service / process name and the associated ACCESS_MASK.


| module | OpenProcess caller function | destination process / destination service | ACCESS\_MASK | ACCESS_MASK translated | comment |
|---------|---------|---------|---------|---------|---------|
| lsadump::lsa /patch | kuhl_m_lsadump_lsa_getHandle() | SamSs | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION | 0x1438 |
| lsadump::lsa /inject | kuhl_m_lsadump_lsa_getHandle() | SamSs | PROCESS_VM_READ \| PROCESS_VM_WRITE  \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION \| PROCESS_CREATE_THREAD | 0x143a |
| lsadump::trust /patch | kuhl_m_lsadump_lsa_getHandle() | SamSs | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION| 0x1438 |
| minesweeper::infos | kuhl_m_minesweeper_infos() | minesweeper.exe | PROCESS_VM_READ \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION | 0x1418 |
| misc:detours | kuhl_m_misc_detours_callback_process() | * |GENERIC_READ | |omitted because of the very generic ACCESS_MASK |
| misc:memssp |  kuhl_m_misc_memssp() | lsass.exe | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION | 0x1438 |
| misc:skeleton|  kuhl_m_misc_skeleton() | lsass.exe | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION | 0x1438 |
| process::suspend, process:stop, process:resume,process:imports, process:exports |kuhl_m_process_genericOperation()|||| omitted because of the very generic ACCESS_MASKs|
| vault::cred /patch|  kuhl_m_vault_cred() | SamSs | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION | 0x1438 | |
| sekurlsa::* | kuhl_m_sekurlsa_acquireLSA() | lsass.exe | PROCESS_VM_READ \| PROCESS_QUERY_INFORMATION | 0x1410 | for Windows Version < 5 |
| sekurlsa::* | kuhl_m_sekurlsa_acquireLSA() | lsass.exe | PROCESS_VM_READ \| PROCESS_QUERY_LIMITED_INFORMATION | 0x1010 | for Windows Version >= 6 |
| token::list, token::elevate, token::run | querying all processes on the system |*||first 0x1400 then 0x40| all three commands result in a call to kull_m_token_getTokens() which first iterates over **all** processes and threads with OpenProcess(PROCESS_QUERY_INFORMATION (0x1400)) (kull_m_token_getTokens_process_callback()) and then again to get the tokens OpenProcess(PROCESS_DUP_HANDLE (0x40)) (in kull_m_handle_getHandlesOfType_callback()) to duplicate the Tokens. This resultet in many thousand (!) Events with ID 10 (!)|
| crypto::cng | kull_m_patch_genericProcessOrServiceFromBuild() via  kuhl_m_crypto_p_cng() |KeyIso | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION | 0x1438 | |
| event::drop | kull_m_patch_genericProcessOrServiceFromBuild() via  kuhl_m_event_drop() | EventLog | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION | 0x1438 | ** this event does not get logged! :O mimikatz seems to be fast enough to apply the patch before the event gets logged!**|
| misc::ncroutemon | kull_m_patch_genericProcessOrServiceFromBuild() via  kuhl_m_misc_ncroutemon() | dsNcService| PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION | 0x1438 | |
| ts::multirdp| kull_m_patch_genericProcessOrServiceFromBuild() via  kuhl_m_ts_multirdp() | TermService | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION | 0x1438 | 
* You could use a stack counting technique to stack all the values of the permissions invoked by processes accessing Lsass.exe. You will have to do some filtering to reduce the number of false positives. You could then group the results with other events such as modules being loaded (EID 7). A time window of 1-2 seconds could help to get to a reasonable number of events for analysis.


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forest
