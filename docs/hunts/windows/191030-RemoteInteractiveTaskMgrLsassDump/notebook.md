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

# Remote Interactive Task Manager LSASS Dump

## Hypothesis

Adversaries might be RDPing to computers in my environment and interactively dumping the memory contents of LSASS with task manager.

## Technical Context



## Offensive Tradecraft

The Windows Task Manager may be used to dump the memory space of lsass.exe to disk for processing with a credential access tool such as Mimikatz.
This is performed by launching Task Manager as a privileged user, selecting lsass.exe, and clicking "Create dump file".
This saves a dump file to disk with a deterministic name that includes the name of the process being dumped.

## Pre-Recorded Security Datasets

| Metadata  |    Value  |
|:----------|:----------|
| docs      | https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-191027055035.html        |
| link      | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip |

### Download Dataset

```{code-cell} ipython3
import requests
from zipfile import ZipFile
from io import BytesIO

url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip'
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

Look for taskmgr creating files which name contains the string lsass and with extension `.dmp`.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| File | Microsoft-Windows-Sysmon/Operational | Process created File | 11 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, Image, TargetFilename, ProcessGuid
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 11
    AND Image LIKE "%taskmgr.exe"
    AND lower(TargetFilename) RLIKE ".*lsass.*\.dmp"
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','Image','TargetFilename','ProcessGuid']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 11)
    & (df['Image'].str.lower().str.endswith('taskmgr.exe', na=False))
    & (df['TargetFilename'].str.lower().str.contains('.*lsass.*dmp', regex=True))
]
)
```

### Analytic II

Look for task manager access lsass and with functions from dbgcore.dll or dbghelp.dll libraries.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process accessed Process | 10 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, SourceImage, TargetImage, GrantedAccess
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 10
    AND lower(SourceImage) LIKE "%taskmgr.exe"
    AND lower(TargetImage) LIKE "%lsass.exe"
    AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','SourceImage','TargetImage','GrantedAccess','CallTrace']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 10)
    & (df['SourceImage'].str.lower().str.endswith('taskmgr.exe', na=False))
    & (df['TargetImage'].str.lower().str.endswith('lsass.exe', na=False))
    & (
        (df['CallTrace'].str.lower().str.contains('.*dbgcore.*', regex=True))
        | (df['CallTrace'].str.lower().str.contains('.*dbghelp.*', regex=True))
    )
]
.head()
)
```

### Analytic III

Look for any process accessing lsass and with functions from dbgcore.dll or dbghelp.dll libraries.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process accessed Process | 10 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, SourceImage, TargetImage, GrantedAccess
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 10
    AND lower(TargetImage) LIKE "%lsass.exe"
    AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','SourceImage','TargetImage','GrantedAccess','CallTrace']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 10)
    & (df['TargetImage'].str.lower().str.endswith('lsass.exe', na=False))
    & (
        (df['CallTrace'].str.lower().str.contains('.*dbgcore.*', regex=True))
        | (df['CallTrace'].str.lower().str.contains('.*dbghelp.*', regex=True))
    )
]
.head()
)
```

### Analytic IV

Look for combinations of process access and process creation to get more context around potential lsass dump form task manager or other binaries.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process accessed Process | 10 |
| Process | Microsoft-Windows-Sysmon/Operational | Process created Process | 1 |

#### Logic

```{code-block}
SELECT o.`@timestamp`, o.Hostname, o.Image, o.LogonId, o.ProcessGuid, a.SourceProcessGUID, o.CommandLine
FROM dataTable o
INNER JOIN (
    SELECT Hostname,SourceProcessGUID
    FROM dataTable
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 10
        AND lower(TargetImage) LIKE "%lsass.exe"
        AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
    ) a
ON o.ProcessGuid = a.SourceProcessGUID
WHERE o.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND o.EventID = 1
```

#### Pandas Query

```{code-cell} Ipython3
processCreateDf = (
df[['@timestamp','Hostname','Image','LogonId','ProcessGuid','CommandLine']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 1)
]
)

processAccessDf = (
df[['@timestamp','Hostname','SourceImage','SourceProcessGUID','TargetImage','GrantedAccess','CallTrace']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 10)
    & (df['TargetImage'].str.lower().str.endswith('lsass.exe', na=False))
    & (
        (df['CallTrace'].str.lower().str.contains('.*dbgcore.*', regex=True))
        | (df['CallTrace'].str.lower().str.contains('.*dbghelp.*', regex=True))
    )
]
)

(
pd.merge(processCreateDf, processAccessDf,
    left_on = 'ProcessGuid', right_on = 'SourceProcessGUID', how = 'inner')
)
```

### Analytic V

Look for binaries accessing lsass that are running under the same logon context of a user over an RDP session.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process accessed Process | 10 |
| Process | Microsoft-Windows-Sysmon/Operational | Process created Process | 1 |
| Authentication log | Microsoft-Windows-Security-Auditing | User authenticated Host | 4778 |

#### Logic

```{code-block}
SELECT o.`@timestamp`, o.Hostname, o.SessionName, o.AccountName, o.ClientName, o.ClientAddress
FROM dataTable o
INNER JOIN (
    SELECT LogonId, Image, CommandLine
    FROM (
        SELECT o.Image, o.LogonId, o.CommandLine
        FROM dataTable o
        INNER JOIN (
            SELECT Hostname,SourceProcessGUID
            FROM dataTable
            WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND EventID = 10
                AND lower(TargetImage) LIKE "%lsass.exe"
                AND (lower(CallTrace) RLIKE ".*dbgcore\.dll.*" OR lower(CallTrace) RLIKE ".*dbghelp\.dll.*")
            ) a
        ON o.ProcessGuid = a.SourceProcessGUID
        WHERE o.Channel = "Microsoft-Windows-Sysmon/Operational"
            AND o.EventID = 1
        )
    ) a
ON o.LogonID = a.LogonId
WHERE lower(o.Channel) = "security"
    AND o.EventID = 4778
```

#### Pandas Query

```{code-cell} Ipython3
processCreateDf = (
df[['@timestamp','Hostname','Image','LogonId','ProcessGuid','CommandLine']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 1)
]
)

processAccessDf = (
df[['@timestamp','Hostname','SourceImage','SourceProcessGUID','TargetImage','GrantedAccess','CallTrace']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 10)
    & (df['TargetImage'].str.lower().str.endswith('lsass.exe', na=False))
    & (
        (df['CallTrace'].str.lower().str.contains('.*dbgcore.*', regex=True))
        | (df['CallTrace'].str.lower().str.contains('.*dbghelp.*', regex=True))
    )
]
)

firstJoinDf = (
pd.merge(processCreateDf, processAccessDf,
    left_on = 'ProcessGuid', right_on = 'SourceProcessGUID', how = 'inner')
)

sessionReconnectDf = (
df[['@timestamp','Hostname','LogonID','SessionName','AccountName','ClientName','ClientAddress']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4778)
]
)

(
pd.merge(firstJoinDf, sessionReconnectDf,
    left_on = 'LogonId', right_on = 'LogonID', how = 'inner')
)
```

## Known Bypasses

## False Positives

## Hunter Notes

* Add context to your queries by joining RDP remote interactive authentication events by the logon ID.

## References
* https://car.mitre.org/analytics/CAR-2019-08-001/
