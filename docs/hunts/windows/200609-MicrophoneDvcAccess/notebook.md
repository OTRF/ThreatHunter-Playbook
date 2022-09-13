---
jupytext:
  formats: md:myst
  text_representation:
    extension: .md
    format_name: myst
    format_version: '1.3'
    jupytext_version: 1.14.1
kernelspec:
  display_name: Python 3
  language: python
  name: python3
---

# Access to Microphone Device

## Hypothesis

Adversaries might be accessing the microphone in endpoints over the network.

## Technical Context



## Offensive Tradecraft

An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.
Based on some research from [@svch0st](https://twitter.com/svch0st) you can to determine when and how long a process had access to the microphone of an endpoint by monitoring the following registry key
  * HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\.

## Pre-Recorded Security Datasets

| Metadata  |    Value  |
|:----------|:----------|
| docs      | https://securitydatasets.com/notebooks/atomic/windows/collection/SDWIN-200609225055.html        |
| link      | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/collection/host/msf_record_mic.zip |

### Download Dataset

```{code-cell} ipython3
import requests
from zipfile import ZipFile
from io import BytesIO

url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/collection/host/msf_record_mic.zip'
zipFileRequest = requests.get(url)
zipFile = ZipFile(BytesIO(zipFileRequest.content))
datasetJSONPath = zipFile.extract(zipFile.namelist()[0])
```

### Read Dataset

```{code-cell} Ipython3
import pandas as pd
from pandas.io import json

df = json.read_json(path_or_buf=datasetJSONPath, lines=True)
```

## Analytics

A few initial ideas to explore your data and validate your detection logic:

### Analytic I

Look for any creation or modification of registry keys under `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged`.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows Registry | Microsoft-Windows-Sysmon/Operational | Process created Windows registry key | 12 |
| Windows Registry | Microsoft-Windows-Sysmon/Operational | Process modified Windows registry key value | 13 |
| Windows Registry | Microsoft-Windows-Sysmon/Operational | Process modified Windows registry key value | 14 |
| Windows Registry | Microsoft-Windows-Sysmon/Operational | Process modified Windows registry key | 14 |

#### Logic

```{code-block}
SELECT EventID, Message
FROM dataTable
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
  AND EventID IN (12,13,14)
  AND LOWER(TargetObject) RLIKE '.*consentstore\\\\\\\microphone.*'
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','EventID','Message']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'].isin([12,13,14]))
    & (df['TargetObject'].str.lower().str.contains('.*consentstore\\\\microphone.*', regex=True))
]
.head()
)
```

### Analytic II

Look for any creation or modification of registry keys under `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged`.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows Registry | Microsoft-Windows-Security-Auditing | Process accessed Windows registry key | 4663 |
| Windows Registry | Microsoft-Windows-Security-Auditing | User accessed Windows registry key | 4663 |
| Windows Registry | Microsoft-Windows-Security-Auditing | Process requested access Windows registry key | 4656 |
| Windows Registry | Microsoft-Windows-Security-Auditing | User requested access Windows registry key | 4656 |
| Windows Registry | Microsoft-Windows-Security-Auditing | Process modified Windows registry key value | 4657 |
| Windows Registry | Microsoft-Windows-Security-Auditing | User modified Windows registry key value | 4657 |

#### Logic

```{code-block}
SELECT EventID, Message
FROM dataTable
WHERE LOWER(Channel) = 'security'
  AND EventID IN (4656,4663,4657)
  AND LOWER(ObjectName) RLIKE '.*consentstore\\\\\\\microphone.*'
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','EventID','Message']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'].isin([4656,4663,4657]))
    & (df['ObjectName'].str.lower().str.contains('.*consentstore\\\\microphone.*', regex=True))
]
.head()
)
```

## Known Bypasses

## False Positives

## Hunter Notes

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry_event/sysmon_susp_mic_cam_access.yml |
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_camera_microphone_access.yml |

## References
* https://medium.com/@7a616368/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072
