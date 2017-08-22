# The ThreatHunter-Playbook
A Threat hunter's playbook to aid the development of techniques and hypothesis for hunting campaigns by leveraging **Sysmon** and **Windows Events** logs. This project will provide specific chains of events exclusively at the host level so that you can take them and develop logic to deploy queries or alerts in your preferred tool or format such as Splunk, ELK, Sigma, GrayLog etc. This repo will follow the structure of the MITRE ATT&CK framework which categorizes post-compromise adversary behavior in tactical groups. In addition, it will provide information about hunting tools/platforms developed by the infosec community for testing and enterprise-wide hunting.


# Goals
* Expedite the development of techniques an hypothesis for hunting campaigns.
* Help Threat Hunters understand patterns of behavior observerd during post-exploitation.
* Reduce the number of false positives while hunting by providing more context around suspicious events.
* Provide enough resources to help on the development of a basic hunting framework for the community.
* Share technical hunt concepts and techniques with others in the community.


# Resources
* [MITRE ATT&CK](https://attack.mitre.org/wiki/Main_Page)
* [MITRE CAR](https://car.mitre.org/wiki/Main_Page)
* [Sqrrl Hunting Techniques](https://sqrrl.com/media/Common-Techniques-for-Hunting.pdf)
* [Sysmon DFIR](https://github.com/MHaggis/sysmon-dfir)
* [CyberWardog Labs Blog](https://cyberwardog.blogspot.com/)
* [MalwareSoup Blog](https://malwaresoup.com/)
* [Threat Hunting Academy](https://threathunting.org/)
* [DFIR and Threat Hunting](http://findingbad.blogspot.com/)


# Tools

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

# Author
* Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

# Contributors
* Andy [@malwaresoup](https://twitter.com/malwaresoup)
* Dimitrios Slamaris [@dim0x69](https://twitter.com/dim0x69)


# Contributing
Can't wait to see other hunters' pull requests with awesome ideas to detect advanced patterns of behavior. The more chains of events you contribute the better this playbook will be for the community.
* Submit Pull requests following the TEMPLATE format.
* Highly recommend to test your chains of events or provide references to back it up before submitting a pull request (Article, whitepaper, hunter notes, etc).
  * Hunter notes are very useful and can help explaining why you would hunt for specific chains of events.
* Feel free to submit pull requests to enhance hunting techniques. #SharingIsCaring

# TO-DO
- [X] Add hunting tools from the community
- [X] Create a hunting techniques document
- [ ] Improve Lateral Movement table format to show source and destination logs
- [ ] Add PowerShell as an option for the table column "source"
- [X] Share HeatMap template for metrics purposes
- [ ] Hunting in Linux & MAC
