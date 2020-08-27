# The ThreatHunter-Playbook

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/OTRF/ThreatHunter-Playbook/master)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Twitter](https://img.shields.io/twitter/follow/HunterPlaybook.svg?style=social&label=Follow)](https://twitter.com/HunterPlaybook)
[![Open Source Love](https://badges.frapsoft.com/os/v3/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

<img src="docs/images/logo/logo.png" width=200>

The Threat Hunter Playbook is a community-based open source project developed to share threat hunting concepts and aid the development of techniques and hypothesis for hunting campaigns by leveraging security event logs from diverse operating systems. This project provides not only information about detections, but also other very important activites when developing analytics such as data documentation, data modeling and even data quality assessments.

In addition, the analytics shared in this project represent specific chains of events exclusively at the host and network level and in a SQL-like format so that you can take them and apply the logic in your preferred tool or query format. The analytics provided in this repo also follow the structure of [MITRE ATT&CK](https://attack.mitre.org/wiki/Main_Page) categorizing post-compromise adversary behavior in tactical groups.

Finally, the project documents detection strategies in the form of [interactive notebooks](https://github.com/OTRF/notebooks-forge#what-is-a-notebook) to provide an easy and flexible way to visualize the expected output and be able to run the analytics against [pre-recorded mordor datasets](https://github.com/hunters-forge/mordor) through [BinderHub](https://mybinder.readthedocs.io/en/latest/index.html) cloud computing environments.

# Goals

* Expedite the development of techniques an hypothesis for hunting campaigns.
* Help Threat Hunters understand patterns of behavior observed during post-exploitation.
* Reduce the number of false positives while hunting by providing more context around suspicious events.
* Share real-time analytics validation examples through cloud computing environments for free.
* Distribute Threat Hunting concepts and processes around the world for free.
* Map pre-recorded datasets to adversarial techniques.
* Accelerate infosec lerning through open source resources.

# A Jupyter Book

I converted the whole repo into a book for you to read and follow as part of the documentation

* https://threathunterplaybook.com/

# Author

Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

# Official Committers

* Jose Luis Rodriguez [@Cyb3rPandaH](https://twitter.com/Cyb3rPandaH) is adding his expertise in data science to it.

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
