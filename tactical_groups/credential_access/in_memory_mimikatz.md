# In-Memory Mimikatz
## Description
Technique of reflectively loading Mimikatz into Memory. Mainly used to dump credentials without touching disk.


## Hypotheis
Adversaries might be executing Mimikatz in memory with the help of PowerShell in order to dump credentials in my environment.


## Events

| Source | EventID | Field | Values | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 10 | GrantedAccess | 0x1010, 0x1410 | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | SourceImage | powershell.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | TargetImage | lsass.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon      | 7       | ImageLoaded   | WinSCard.dll, cryptdll.dll, hid.dll, samlib.dll, vaultcli.dll, WMINet_Utils.dll (Optional) |
| [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html) |


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
