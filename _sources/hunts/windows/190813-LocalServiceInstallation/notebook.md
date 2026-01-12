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

# Local Service Installation

## Hypothesis

Adversaries might be creating new services to execute code on a compromised endpoint in my environment

## Technical Context



## Offensive Tradecraft

Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager.
This can be done by by adversaries creating a new service.

## Pre-Recorded Security Datasets

| Metadata  |    Value  |
|:----------|:----------|
| docs      | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-190518210652.html        |
| link      | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip |

### Download Dataset

```{code-cell} ipython3
import requests
from zipfile import ZipFile
from io import BytesIO

url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip'
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

Look for new services being created in your environment and stack the values of it

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Service | Microsoft-Windows-Security-Auditing | User created Service | 4697 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, SubjectUserName, ServiceName, ServiceType, ServiceStartType, ServiceAccount
FROM dataTable
WHERE LOWER(Channel) = "security" AND EventID = 4697
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','SubjectUserName','ServiceName','ServiceType','ServiceStartType','ServiceAccount']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4697)
]
)
```

## Known Bypasses

## False Positives

## Hunter Notes

* If there are a lot of unique services being created in your environment, try to categorize the data based on the bussiness unit.
* Identify the source of unique services being created everyday. I have seen Microsoft applications doing this.
* Stack the values of the service file name associated with the new service.
* Document what users create new services across your environment on a daily basis

## References
* https://www.powershellempire.com/?page_id=523
