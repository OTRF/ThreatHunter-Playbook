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

# WDigest Downgrade

## Hypothesis

Adversaries might have updated the property value UseLogonCredential of HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to 1 in order to be able to extract clear text passwords from memory contents of lsass.

## Technical Context

Windows 8.1 introduced a registry setting that allows for disabling the storage of the users logon credential in clear text for the WDigest provider.

## Offensive Tradecraft

This setting can be modified in the property UseLogonCredential for the registry key HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest.
If this key does not exists, you can create it and set it to 1 to enable clear text passwords.

## Pre-Recorded Security Datasets

| Metadata  |    Value  |
|:----------|:----------|
| docs      | https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-190518201922.html        |
| link      | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/empire_wdigest_downgrade.tar.gz |

### Download Dataset

```{code-cell} ipython3
import requests
from zipfile import ZipFile
from io import BytesIO

url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/empire_wdigest_downgrade.tar.gz'
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

Look for any process updating UseLogonCredential registry key value.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows registry | Microsoft-Windows-Sysmon/Operational | Process modified Windows registry key value | 13 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, Image, TargetObject
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 13
    AND TargetObject LIKE "%UseLogonCredential"
    AND Details = 1
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','Image','TargetObject']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 13)
    & (df['TargetObject'].str.endswith('UseLogonCredential', na=False))
    & (df['Details'] == 1)
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
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry_event/sysmon_wdigest_enable_uselogoncredential.yml |

## References
* https://github.com/samratashok/nishang/blob/master/Gather/Invoke-MimikatzWDigestDowngrade.ps1
* https://blog.stealthbits.com/wdigest-clear-text-passwords-stealing-more-than-a-hash/
