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

# Wuauclt CreateRemoteThread Execution

## Hypothesis

Adversaries might be proxy executing code via the Windows Update client utility in my environment and creating and running a thread in the virtual address space of another process via the CreateRemoteThread API to bypass rules looking for it calling out to the Internet.

## Technical Context

The Windows Update client (wuauclt.exe) utility allows you some control over the functioning of the Windows Update Agent.

## Offensive Tradecraft

Adversaries can leverage this utility to proxy the execution of code by specifying an arbitrary DLL with the following command line `wuauclt.exe /UpdateDeploymentProvider <Full_Path_To_DLL> /RunHandlerComServer`

## Pre-Recorded Security Datasets

| Metadata  |    Value  |
|:----------|:----------|
| docs      | https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-201012183248.html        |
| link      | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/covenant_lolbin_wuauclt_createremotethread.zip |

### Download Dataset

```{code-cell} ipython3
import requests
from zipfile import ZipFile
from io import BytesIO

url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/covenant_lolbin_wuauclt_createremotethread.zip'
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

Look for wuauclt with the specific parameters used to load and execute a DLL.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process created Process | 1 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, Image, CommandLine
FROM dataTable
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
    AND EventID = 1
    AND Image LIKE '%wuauclt.exe'
    AND CommandLine LIKE '%wuauclt%UpdateDeploymentProvider%.dll%RunHandlerComServer'
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','Image','CommandLine']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 1)
    & (df['Image'].str.lower().str.endswith('wuauclt.exe', na=False))
    & (df['CommandLine'].str.lower().str.contains('.*wuauclt.*updatedeploymentprovider.*.dll.*runhandlercomserver.*', regex=True))
]
.head()
)
```

### Analytic II

Look for unsigned DLLs being loaded by wuauclt. You might have to stack the results and find potential anomalies over time.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Module | Microsoft-Windows-Sysmon/Operational | Process loaded DLL | 7 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, Image, ImageLoaded
FROM dataTable
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
    AND EventID = 7
    AND Image LIKE '%wuauclt.exe'
    AND Signed = 'false'
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','Image','ImageLoaded']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 7)
    & (df['Image'].str.lower().str.endswith('wuauclt.exe', na=False))
    & (df['Signed'] == 'false')
]
.head()
)
```

### Analytic III

Look for wuauclt creating and running a thread in the virtual address space of another process via the CreateRemoteThread API.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process wrote_to Process | 8 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, TargetImage
FROM dataTable
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
    AND EventID = 8
    AND SourceImage LIKE '%wuauclt.exe'
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','SourceImage','TargetImage']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 8)
    & (df['SourceImage'].str.lower().str.endswith('wuauclt.exe', na=False))
]
.head()
)
```

### Analytic IV

Look for recent files created being loaded by wuauclt.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| File | Microsoft-Windows-Sysmon/Operational | Process created File | 11 |
| File | Microsoft-Windows-Sysmon/Operational | Process loaded DLL | 7 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, ImageLoaded
FROM dataTable b
INNER JOIN (
    SELECT TargetFilename, ProcessGuid
    FROM dataTable
    WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
        AND EventID = 11
    ) a
ON b.ImageLoaded = a.TargetFilename
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
  AND EventID = 7
  AND Image LIKE '%wuauclt.exe'
```

#### Pandas Query

```{code-cell} Ipython3
imageLoadDf = (
df[['@timestamp','Hostname','Image','ImageLoaded']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 7)
    & (df['Image'].str.lower().str.endswith('wuauclt.exe', na=False))
]
)

fileCreateDf = (
df[['@timestamp','Hostname','Image','TargetFilename']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 11)
]
)

(
pd.merge(imageLoadDf, fileCreateDf,
    left_on = 'ImageLoaded', right_on = 'TargetFilename', how = 'inner')
)
```

### Analytic V

Look for wuauclt loading recently created DLLs and writing to another process.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Module | Microsoft-Windows-Sysmon/Operational | Process created File | 11 |
| Module | Microsoft-Windows-Sysmon/Operational | Process loaded DLL | 7 |
| Module | Microsoft-Windows-Sysmon/Operational | Process wrote_to Process | 8 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, d.TargetImage, c.ImageLoaded
FROM dataTable d
INNER JOIN (
    SELECT b.ProcessGuid, b.ImageLoaded
    FROM dataTable b
    INNER JOIN (
      SELECT TargetFilename, ProcessGuid
      FROM dataTable
      WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
          AND EventID = 11
    ) a
    ON b.ImageLoaded = a.TargetFilename
    WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
      AND EventID = 7
      AND Image LIKE '%wuauclt.exe'
) c
ON d.SourceProcessGuid = c.ProcessGuid
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
      AND EventID = 8
      AND SourceImage LIKE '%wuauclt.exe'
```

#### Pandas Query

```{code-cell} Ipython3
imageLoadDf = (
df[['@timestamp','Hostname','Image','ImageLoaded','ProcessGuid']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 7)
    & (df['Image'].str.lower().str.endswith('wuauclt.exe', na=False))
]
)

fileCreateDf = (
df[['@timestamp','Hostname','Image','TargetFilename','ProcessGuid']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 11)
]
)

firstJoinDf = (
pd.merge(imageLoadDf, fileCreateDf,
    left_on = 'ImageLoaded', right_on = 'TargetFilename', how = 'inner')
)

createRTDf = (
df[['@timestamp','Hostname','SourceImage','SourceProcessGuid','TargetImage']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 8)
    & (df['SourceImage'].str.lower().str.endswith('wuauclt.exe', na=False))
]
)

(
pd.merge(firstJoinDf, createRTDf,
    left_on = 'ProcessGuid_x', right_on = 'SourceProcessGuid', how = 'inner')
)
```

## Known Bypasses

## False Positives

## Hunter Notes

* Baseline your environment to identify normal activity from wuauclt. You will have to do some stacking on images loaded by wuauclt (Split it on signed and un-signed (if applicable))

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/sysmon_proxy_execution_wuauclt.yml |
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/sysmon_proxy_execution_wuauclt.yml |
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_lolbas_execution_of_wuauclt.yml |

## References
* https://dtm.uk/wuauclt/
* https://docs.microsoft.com/zh-cn/security-updates/windowsupdateservices/21740782
* https://github.com/Neo23x0/sigma/blob/2cb540f95ed2d02f7d8a2bf84d9bf4a5962f156d/rules/windows/process_creation/sysmon_proxy_execution_wuauclt.yml
