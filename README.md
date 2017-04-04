# The ThreatHunter-Playbook
A Threat hunter's playbook to aid the development of techniques and hypothesis for hunting campaigns by leveraging **Sysmon** and **Windows Events** logs. This project will provide specific chains of events exclusively at the host level so that you can take them and develop logic to deploy queries or alerts in your preferred tool or format such as Splunk, ELK, Sigma, GrayLog etc. This repo will follow the structure of the MITRE ATT&CK framework which categorizes post-compromise adversary behavior in tactical groups. 


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


# Author
* Roberto Rodriguez @Cyb3rWard0g

# Contributors
* Andy @malwaresoup
* Michael Haggis @M_Haggis

# Contributing
Can't wait to see other hunters' pull requests with awesome ideas to detect advanced patterns of behavior. The more chains of events you contribute the better this playbook will be for the community.
* Submit Pull requests following the TEMPLATE format.
* Highly recommend to test your chains of events or provide references to back it up before submitting a pull request (Article, whitepaper, hunter notes, etc).
  * Hunter notes are very useful and can help explaining why you would hunt for specific chains of events.
* Feel free to submit pull requests to enhance hunting techniques. #SharingIsCaring
