# Mimikatz Skeleton Key
## Technique ID
T1098


## Description
Skeleton Key is used to patch an enterprise domain controller authentication process with a backdoor password. It allows adversaries to bypass the standard authentication system to use a defined password for all accounts authenticating to that domain controller [Source](http://www.secureworks.com/cyber-threat-intelligence/threats/skeleton-key-malware-analysis/).
 
Key Points: [Source](http://adsecurity.org/?p=1255)
* Requires domain-level admin rights (and debug rights which admins have by default) to “patch” LSASS on a Domain Controller.
* All existing user account passwords continue working as normal.
* Adds a new password that enables the attacker to log on as any user with this password – this is the “skeleton key”.
* Active Directory Domain Controllers may experience replication issues.
* User accounts that require a smart card for authentication are not affected.
* The Skeleton Key malware currently doesn’t remain active after a reboot – rebooting the DCs removes the in-memory patch. Note that DCs are typically only rebooted about once a month.
* The Skeleton Key malware only works on the following 64-bit systems: Windows Server 2008, Windows Server 2008 R2, and Windows Server 2003 R2.
* Performs Kerberos encryption downgrade to RC4_HMAC_MD5
* Mimikatz now has skeleton key functionality and seems to work on all versions of Windows Server…
* Protect your Active Directory admin accounts and don’t let untrusted code run on Domain Controllers

Mimikatz Command: 
* misc::skeleton : Inject Skeleton Key into LSASS process on Domain Controller. This enables all user authentication to the Skeleton Key patched DC to use a “master password” (aka Skeleton Keys) as well as their usual password.

Monitoring OpenProcess(): [dim0x69 - blog.3or.de](https://blog.3or.de/hunting-mimikatz-with-sysmon-monitoring-openprocess.html)

| module | OpenProcess caller function | destination process / destination service | ACCESS\_MASK | ACCESS_MASK Code | comment |
|---------|---------|---------|---------|---------|---------|
| misc:skeleton| kuhl_m_misc_skeleton() | lsass.exe | PROCESS_VM_READ \| PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_QUERY_INFORMATION | 0x1438 |


## Hypothesis
Adversaries might be injecting a skeleton key into LSASS on Domain Controllers by running Mimikatz withing my organization


## Attack Simulation


| Script  | Short Description | Author | 
|---------|---------|---------|
| [mimikatz](https://github.com/gentilkiwi/mimikatz)| "misc::skeleton" Inject Skeleton Key into LSASS process on Domain Controller.| [Benjamin Delpy](http://blog.gentilkiwi.com/) |


## Recommended Data Sources

| ATT&CK Data Source | Event Log | Description |
|---------|---------|---------|
|Process Monitoring| Sysmon | Process access | 
|Process Monitoring| Sysmon |Process creation |
|Process Monitoring| Sysmon |Image Loaded
|Process Monitoring| Security |Process creation | 
|PowerShell Logs| PowerShell |Module Logging |
|PowerShell Logs| PowerShell |Script-Block Logging |
|Sensitive Privilege Use| Windows Security Auditing |Audit Sensitive Privilege Use |
## Specific Events

| Source | EventID | EventFields | Details | Reference | 
|--------|---------|-------|--------|-----------| 
| Sysmon | 10 | GrantedAccess |0x1438| [dim0x69 - blog.3or.de](https://blog.3or.de/hunting-mimikatz-with-sysmon-monitoring-openprocess.html) |
| Sysmon | 10 | SourceImage | powershell.exe OR ANY | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | TargetImage | lsass.exe | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 10 | CallTrace | \\\ntdll\\.dll\\+\[a-zA-Z0-9\]\{1,\}\|\\\KERNELBASE\\.dll\\+\[a-zA-Z0-9\]\{1,\}\|UNKNOWN\(\[a-zA-Z0-9\]\{16\}\) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html) |
| Sysmon | 7 | ImageLoaded | WinSCard.dll, cryptdll.dll, hid.dll, samlib.dll, vaultcli.dll, WMINet_Utils.dll (Optional) | [Cyb3rWard0g](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html) |
| WinEvent | 4673 | ServiceName | LsaRegisterLogonProcess() | [PyroTek3](https://adsecurity.org/?p=1275) |
| WinEvent | 4673 | ProcessName | lsass.exe | [PyroTek3](https://adsecurity.org/?p=1275) |
| WinEvent | 4611 | LogonProcessName | ConsentUI | [PyroTek3](https://adsecurity.org/?p=1275) |

## Recommended Configuration(s)
| Title | Description | Reference|
|---------|---------|---------|
| Mimikatz in memory skeleton key | Sysmon configuration | [T1098\_mimikatz\_inmem.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T1098_mimikatz_inmem.xml)
|  Audit Sensitive Privilege Use | You will need to enable an Audit Policy of Privilege Use Category -> Sub-category Audit Sensitive Privilege Use | [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4673#security-monitoring-recommendations) |


## Data Analytics 

| Analytic Type  | Analytic Logic | Analytic Data Object |
|--------|---------|---------|
| Anomaly/Outlier | process WHERE target\_process\_name == "lsass.exe" AND process\_granted\_access == "0x1438" WHERE image\_loaded\_name == "WinSCard.dll" AND image\_loaded\_name == "cryptdll.dll" AND image\_loaded\_name == "hid.dll" AND image\_loaded\_name == "samlib.dll" AND image\_loaded\_name == "vaultcli.dll" AND image\_loaded\_name == "WMINet_Utils.dll" | [process](https://github.com/Cyb3rWard0g/OSSEM/blob/c0bf44fb8c527f6e678c4ff1321814108e024315/detection_data_model/data_objects/process.md) |



## Hunter Notes
* Most likely, your adversary will be executing Mimikatz in memory. Therefore, monitoring for modules being loaded in your DC will be really helpful. If you do not want to monitor for every single module (Noise), I would recommend to monitor at least for the 6 modules from Sysmon EID 7 provided above.
	* You can start stacking the processes in your DCs loading all those modules at once (The combination is rare)
* Stack the GrantedAccess codes utilized to access your Lsass.exe process in your DCs.
	* Look for code 0x1438 after stacking all the codes from Sysmon EID 10.
	* Thats usually an injection behavior.
* Look for processes accessing Lsass.exe with a potential CallTrace Pattern: C:\\Windows\\SYSTEM32\\ntdll\.dll\+[a-zA-Z0-9]{1,}\|C:\\Windows\\system32\\KERNELBASE\.dll\+[a-zA-Z0-9]{1,}\|UNKNOWN\([a-zA-Z0-9]{16}\)
* Stack Sensitive privilege usage and Registration of trusted logon processes with the Local Security Authority events in your DCs, and group them with the events from above. Use timestamps to add context (bucket of 5 seconds maybe?)


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [X] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
