# In-Memory Mimikatz
## Description
Technique of reflectively loading Mimikatz into Memory. Mainly used to dump credentials without touching disk.


## Hypotheis
Adversaries might be executing Mimikatz in memory with the help of PowerShell in order to dump credentials in my environment.


## Events

| Source | EventID | Event Name    | Values                                                                                | Author      | References                                                                                                                                                                     |
|-------------|---------|---------------|---------------------------------------------------------------------------------------|-------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Sysmon      | 10      | GrantedAccess | 0x1010, 0x1410                                                                         | Cyb3rWard0g | https://goo.gl/mmw7Bk |
| Sysmon      | 7       | ImageLoaded   | WinSCard.dll, cryptdll.dll, hid.dll, samlib.dll, vaultcli.dll, WMINet_Utils.dll (Optional) | Cyb3rWard0g | https://goo.gl/Z1AQz3 |


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
