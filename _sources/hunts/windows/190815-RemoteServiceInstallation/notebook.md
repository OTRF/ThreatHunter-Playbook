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

# Remote Service creation

## Hypothesis

Adversaries might be creating new services remotely to execute code and move laterally in my environment

## Technical Context



## Offensive Tradecraft

Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager. This can be done by by adversaries creating a new service.
Adversaries can create services remotely to execute code and move lateraly across the environment.

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

### Analytic I

Look for new services being created in your environment under a network logon session (3). That is a sign that the service creation was performed from another endpoint in the environment.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Service | Microsoft-Windows-Security-Auditing | User created Service | 4697 |
| Authentication log | Microsoft-Windows-Security-Auditing | User authenticated Host | 4624 |

#### Logic

```{code-block}
SELECT o.`@timestamp`, o.Hostname, o.SubjectUserName, o.SubjectUserName, o.ServiceName, a.IpAddress
FROM dataTable o
INNER JOIN (
    SELECT Hostname,TargetUserName,TargetLogonId,IpAddress
    FROM dataTable
    WHERE LOWER(Channel) = "security"
        AND EventID = 4624
        AND LogonType = 3            
        AND NOT TargetUserName LIKE "%$"
    ) a
ON o.SubjectLogonId = a.TargetLogonId
WHERE LOWER(o.Channel) = "security"
    AND o.EventID = 4697
```

#### Pandas Query

```{code-cell} Ipython3
serviceInstallDf= (
df[['@timestamp','Hostname','SubjectUserName','SubjectLogonId','ServiceName','ServiceType']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4697)
]
)

networkLogonDf = (
df[['@timestamp', 'Hostname', 'TargetUserName', 'TargetLogonId', 'IpAddress']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4624)
    & (df['LogonType'] == 3)
    & (~df['SubjectUserName'].str.endswith('$', na=False))
]
)

(
pd.merge(serviceInstallDf, networkLogonDf,
  left_on = 'SubjectLogonId', right_on = 'TargetLogonId', how = 'inner')
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
