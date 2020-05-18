# APT 29

|               |    |
|:--------------|:---|
| Group         | APT29 |
| ATT&CK Group ID | G0016 |
| ATT&CK STIX ID | [intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542](https://github.com/mitre/cti/blob/b8b9e39cfd2acdc3b0cf4fbd09c29a7732af0e1d/enterprise-attack/intrusion-set/intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542.json) |
| Aliases | APT29, YTTRIUM, The Dukes, Cozy Bear, CozyDuke |

## Description

[APT29](https://attack.mitre.org/groups/G0016/) is a threat group that has been attributed to the Russian government and has operated since at least 2008. This group reportedly compromised the Democratic National Committee starting in the summer of 2015.

APT29 is distinguished by its commitment to stealth and sophisticated implementations of techniques via an arsenal of custom malware. APT29 typically accomplishes its goals via custom compiled binaries and alternate execution methods such as PowerShell and WMI. APT29 has also been known to employ various operational cadences (smash-and-grab vs. slow-and-deliberate) depending on the perceived intelligence value and/or infection method of victims. 

## ATT&CK Evaluation 

There are several datasets as a result of me replicating APT29 activity from the [ATT&CK evaluations (Round 2)](https://attackevals.mitre.org/evaluations.html?round=APT29)
* [First Scenario](https://github.com/mitre-attack/attack-arsenal/tree/master/adversary_emulation/APT29/Emulation_Plan/Day%201)
* [Second Scenario](https://github.com/mitre-attack/attack-arsenal/tree/master/adversary_emulation/APT29/Emulation_Plan/Day%202)