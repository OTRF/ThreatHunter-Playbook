# Resources
Helpful resources to learn a little bit more about Threat Hunting.

# Goals
* Gather as many resources as I can about Threat Hunting to share them with the community all at once.
* Share interesting/valuable resources that helped me and others to learn more about Threat Hunting.

# Types of Resources

## Papers

| Name | Description | Author | Reference |
|--------|---------|-------|-------|
| Finding Cyber Threats With ATT&CK-Based Analytics | This paper presents a methodology for using the MITRE ATT&CK framework, a behavioral-based threat model, to identify relevant defensive sensors and build, test, and refine behavioral-based analytic detection capabilities using adversary emulation | [@MITREattack](https://twitter.com/MITREattack) | [Paper](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/resources/papers/16-3713-finding-cyber-threats%20with%20att%26ck-based-analytics.pdf) | 
| Advanced Threat Detection And Response | Using Splunk software to defend against advanced threats  | [Splunk](https://www.splunk.com/) | [Paper](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/resources/papers/advanced-threat-detection-and-response-tech-brief.pdf) |
| Network Profiling Using Flow | This report provides a step-by-step guide for profiling—discovering public-facing assets on a network—using network flow (netflow) data | [SEI](http://www.sei.cmu.edu/) | [Paper](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/resources/papers/Network_Profiling_Using_Flow.pdf) |
| Detecting Lateral Movement through Tracking Event Logs |  the Japan Computer Emergency Response Team Coordination Center (JPCERT/CC) extracted tools used by many attackers by investigating recently confirmed cases of targeted attacks. Then, a research was conducted to investigate what kind of logs were left on the server and clients by using such tools, and what settings need to be configured to obtain logs that contain sufficient evidential information | [@jpcert](https://twitter.com/jpcert) | [Paper](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/resources/papers/20170612_Detecting_LM.pdf) |

## Presentations

| Session Title | Description | Speaker | Reference |
|--------|---------|-------|-------|
| Building A Successful Internal Adversarial Simulation Team |  | [@carnal0wnage](https://twitter.com/carnal0wnage) & [indi303](https://twitter.com/indi303) | [Video](https://www.youtube.com/watch?v=Q5Fu6AvXi_A&feature=youtu.be) |
| Go to Hunt Then Sleep | You know you should be hunting for these threats, but where do you start?  | [@DavidJBianco](https://twitter.com/DavidJBianco) | [Slides](https://speakerdeck.com/davidjbianco/go-to-hunt-then-sleep) |
| Advanced Incident Detection and Threat Hunting using Sysmon and Splunk | Introduction on Sysmon and public resources. Brief recap of BotConf talk with examples. Threat Hunting & Advanced Detection examples. | [@c_APT_ure](https://twitter.com/c_APT_ure) | [Slides](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/blob/master/resources/presentations/FIRST-2017_Tom-Ueltschi_Sysmon_FINAL.pdf) |

## Blog Posts

| Name | Description | Author| Reference |
|--------|---------|-------|-------|
| Host-based Threat Modeling & Indicator Design | This post explicitly lays out SpecterOps’ methodology surrounding threat modeling and design of defensive indicators. | [@jaredatkinson](https://twitter.com/jaredcatkinson) | [Post](https://posts.specterops.io/host-based-threat-modeling-indicator-design-a9dbbb53d5ea) |
| Hunting in Memory | Low noise approach to hunting for adversaries that are hiding in memory. | [@dez_](https://twitter.com/dez_) | [Post](https://www.endgame.com/blog/technical-blog/hunting-memory)|
| Building Operational Threat Hunting Models | 5 Threat Hunting Models that can be used to frame discussions about a threat hunting program and its objectives.  | [@kathayra](https://twitter.com/kathayra) | [Post](https://happythreathunting.blogspot.com/2017/08/building-operational-threat-hunting.html) |

## Tools

| Name | Description | Author |
|--------|---------|-------|
| [Hunter](https://github.com/ThreatHuntingProject/hunter) | A threat hunting / data analysis environment based on Python, Pandas, PySpark and Jupyter Notebook | [@DavidJBianco](https://twitter.com/DavidJBianco) | 
| [Clearcut](https://github.com/DavidJBianco/Clearcut) | Clearcut is a tool that uses machine learning to help you focus on the log entries that really need manual review | [@DavidJBianco](https://twitter.com/DavidJBianco) |
| [Assimilate](https://github.com/soinull/assimilate) | Assimilate is a series of python scripts for using the Naïve Bayes algorithm to find potential malicious activity in HTTP headers | [@Soinull](https://twitter.com/Soinull) | 
| [Appcompatprocessor](https://github.com/mbevilacqua/appcompatprocessor) | A tool designed to efficiently process and analyse ShimCache and AmCache data at scale for enterprise-wide hunting purposes | Matias Bevilacqua | 
| [Get-InjectedThreat](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2) | A pure powershell tool built on PSReflect that allows a hunter to automatically analyze memory across systems and rapidly highlight injected in-memory-only attacks across systems at scale | [@jaredcatkinson](https://twitter.com/jaredcatkinson) & [@dez_](https://twitter.com/dez_) _| 
| [ACE](https://github.com/Invoke-IR/ACE) | The Automated Collection and Enrichment (ACE) platform is a suite of tools for threat hunters to collect data from many endpoints in a network and automatically enrich the data. The data is collected by running scripts on each computer without installing any software on the target. ACE supports collecting from Windows, macOS, and Linux hosts | [@jaredcatkinson](https://twitter.com/jaredcatkinson) & [@robwinchester3](https://twitter.com/robwinchester3) |
| [NOAH](https://github.com/giMini/NOAH) | NOAH is an agentless open source Incident Response framework based on PowerShell, called "No Agent Hunting" (NOAH), to help security investigation responders to gather a vast number of key artifacts without installing any agent on the endpoints saving precious time | [@pabraeken](https://twitter.com/pabraeken) |
| [Invoke-ATTACKAPI](https://github.com/Cyb3rWard0g/Invoke-ATTACKAPI) | A PowerShell script to interact with the MITRE ATT&CK Framework via its own API in order to gather information about techniques, tactics, groups, software and references provided by the MITRE ATT&CK Team @MITREattack. Very helpful to identify use cases for hunting campaigns. | [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g) | 