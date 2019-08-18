# The ThreatHunter-Playbook

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/Cyb3rWard0g/ThreatHunter-Playbook/master)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub issues-closed](https://img.shields.io/github/issues-closed/Cyb3rward0g/ThreatHunter-Playbook.svg)](https://GitHub.com/Cyb3rWard0g/ThreatHunter-Playbook/issues?q=is%3Aissue+is%3Aclosed)
[![Twitter](https://img.shields.io/twitter/follow/HunterPlaybook.svg?style=social&label=Follow)](https://https://twitter.com/HunterPlaybook)
[![Open Source Love svg1](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

<img src="resources/images/LOGO.png" width=200>

A Threat hunter's playbook to aid the development of techniques and hypothesis for hunting campaigns by leveraging security event logs from diverse operating systems. This project provides specific chains of events exclusively at the host and network level so that you can take them and develop logic to develop data analytics in your preferred tool or query format. This repo follows the structure of the [MITRE ATT&CK](https://attack.mitre.org/wiki/Main_Page) framework categorizing post-compromise adversary behavior in tactical groups. In addition, it will provide information about hunting tools/platforms developed by the infosec community for testing and enterprise-wide hunting.

# Goals

* Expedite the development of techniques an hypothesis for hunting campaigns.
* Help Threat Hunters understand patterns of behavior observed during post-exploitation.
* Reduce the number of false positives while hunting by providing more context around suspicious events.
* Provide resources and technical hunt concepts to help on the development of a basic hunting framework for the community

# Author

* Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)
* Jose Luis Rodriguez [@Cyb3rPandaH](https://twitter.com/Cyb3rPandaH)

# Contributing

Can't wait to see other hunters' pull requests with awesome ideas to detect advanced patterns of behavior. The more chains of events you contribute the better this playbook will be for the community.
* Submit Pull requests following the TEMPLATE format.
* Highly recommend to test your chains of events or provide references to back it up before submitting a pull request (Article, whitepaper, hunter notes, etc).
  * Hunter notes are very useful and can help explaining why you would hunt for specific chains of events.
* Feel free to submit pull requests to enhance hunting techniques. #SharingIsCaring

# To-Do

* [ ] OSX & Linux Playbooks
* [ ] Cloud AWS Playbooks
* [ ] Update Binder Libraries (Testing)
