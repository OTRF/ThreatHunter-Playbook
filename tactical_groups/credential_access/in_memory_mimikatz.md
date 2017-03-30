# In-Memory Mimikatz
## Description
Technique of reflectively loading Mimikatz into Memory. Mainly used to dump credentials without touching disk.


## Hypotheis
Adversaries might be executing Mimikatz in memory with the help of PowerShell in order to dump credentials in my environment.


## Events

| Source | EventID | Fields | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 10 | GrantedAccess | 0x1010, 0x1410 | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | SourceImage | powershell.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | TargetImage | lsass.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | CallTrace | \\\ntdll\\.dll\\+\[a-zA-Z0-9\]\{1,\}\|\\\KERNELBASE\\.dll\\+\[a-zA-Z0-9\]\{1,\}\|UNKNOWN\(\[a-zA-Z0-9\]\{16\}\) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 7 | ImageLoaded | WinSCard.dll, cryptdll.dll, hid.dll, samlib.dll, vaultcli.dll, WMINet_Utils.dll (Optional) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html) |

## Hunter Notes
* GrantedAccess code 0x1010 is the new permission Mimikatz v.20170327 uses for command "sekurlsa::logonpasswords"
  * 0X00000010 = VMRead
  * 0x00001000 = QueryLimitedInfo
* GrantedAccess code 0x1010 is less common than 0x1410
* Out of all the Modules that Mimikatz needs to function, the 5 above are the ones with less false positives
* WMINet_Utils.dll is optional since it is loaded by scripts developed by PowerSploit and Empire projects (Invoke-Mimikatz.ps1).
* Look for PowerShell.exe accessing Lsass.exe with a potential CallTrace Pattern: C:\\Windows\\SYSTEM32\\ntdll\.dll\+[a-zA-Z0-9]{1,}\|C:\\Windows\\system32\\KERNELBASE\.dll\+[a-zA-Z0-9]{1,}\|UNKNOWN\([a-zA-Z0-9]{16}\)


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
