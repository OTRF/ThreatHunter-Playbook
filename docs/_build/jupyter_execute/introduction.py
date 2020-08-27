# Introduction

[![](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![](https://img.shields.io/twitter/follow/HunterPlaybook.svg?style=social&label=Follow)](https://twitter.com/HunterPlaybook)
[![](https://badges.frapsoft.com/os/v3/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

The Threat Hunter Playbook is a community-based open source project developed to share threat hunting concepts and aid the development of techniques and hypothesis for hunting campaigns by leveraging security event logs from diverse operating systems. This project provides not only information about detections, but also other very important activites when developing analytics such as data documentation, data modeling and even data quality assessments.

In addition, the analytics shared in this project represent specific chains of events exclusively at the host and network level and in a SQL-like format so that you can take them and apply the logic in your preferred tool or query format. The analytics provided in this repo also follow the structure of [MITRE ATT&CK](https://attack.mitre.org/wiki/Main_Page) categorizing post-compromise adversary behavior in tactical groups.

Finally, the project documents detection strategies in the form of [interactive notebooks](https://github.com/OTRF/notebooks-forge#what-is-a-notebook) to provide an easy and flexible way to visualize the expected output and be able to run the analytics against [pre-recorded mordor datasets](https://github.com/OTRF/mordor) through [BinderHub](https://mybinder.readthedocs.io/en/latest/index.html) cloud computing environments.

## Goals

* Expedite the development of techniques an hypothesis for hunting campaigns.
* Help Threat Hunters understand patterns of behavior observed during post-exploitation.
* Reduce the number of false positives while hunting by providing more context around suspicious events.
* Share real-time analytics validation examples through cloud computing environments for free.
* Distribute Threat Hunting concepts and processes around the world for free.
* Map pre-recorded datasets to adversarial techniques.
* Accelerate infosec lerning through open source resources.

## Author

Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

## Official Committers

* Jose Luis Rodriguez [@Cyb3rPandaH](https://twitter.com/Cyb3rPandaH) is adding his expertise in data science to it.

## Acknowledgements

Jupyter Books was originally created by [Sam Lau](http://www.samlau.me/) and [Chris Holdgraf](https://predictablynoisy.com/) with support of the **UC Berkeley Data Science Education Program and the [Berkeley Institute for Data Science](https://bids.berkeley.edu/)**




```{toctree}
:hidden:
:titlesonly:
:caption: Pre-Hunt Activities

pre-hunt/data_management
```


```{toctree}
:hidden:
:titlesonly:
:caption: Campaign Notebooks

evals/intro
```


```{toctree}
:hidden:
:titlesonly:
:caption: Targeted Notebooks

notebooks/windows/windows
notebooks/linux/linux
notebooks/mac/mac
```


```{toctree}
:hidden:
:titlesonly:
:caption: Tutorials

tutorials/jupyter/introduction
```
