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

# SMB Create Remote File

## Hypothesis

Adversaries might be creating a file remotely via the Server Message Block (SMB) Protocol.

## Technical Context

Client systems use the Common Internet File System (CIFS) Protocol to request file and print services from server systems over a network. CIFS is a stateful protocol, in which clients establish a session with a server and use that session to make a variety of requests to access files, printers, and inter-process communication (IPC) mechanisms, such as named pipes.
The extended CIFS Protocol is known as the Server Message Block (SMB). The SMB2 CREATE Request packet is sent by a client to request either creation of or access to a file. In case of a named pipe or printer, the server MUST create a new file.

## Offensive Tradecraft

Adversaries leverage SMB to copy files over the network to either execute code remotely or exfiltrate data.

## Pre-Recorded Security Datasets

| Metadata  |    Value  |
|:----------|:----------|
| docs      | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200806015757.html        |
| link      | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/covenant_copy_smb_CreateRequest.zip |

### Download Dataset

```{code-cell} ipython3
import requests
from zipfile import ZipFile
from io import BytesIO

url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/covenant_copy_smb_CreateRequest.zip'
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

Look for non-system accounts SMB connecting (Tree Connect) to a file share that is not `IPC$`.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| File | Microsoft-Windows-Security-Auditing | User accessed file share | 5140 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, ShareName, SubjectUserName, SubjectLogonId,  AccessMask
FROM dataTable
WHERE LOWER(Channel) = 'security'
    AND (EventID = 5140)
    AND NOT ShareName LIKE '%IPC$'
    AND NOT SubjectUserName LIKE '%$'
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','ShareName','SubjectUserName','SubjectLogonId','AccessMask']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 5140)
    & (~df['ShareName'].str.contains('.*IPC.*', regex=True, na=True))
    & (~df['SubjectUserName'].str.endswith('$', na=False))
]
.head()
)
```

### Analytic II

Look for non-system accounts SMB connecting (Tree Connect) to an `IPC$` Share and administrative shares (i.e C$) with the same logon session ID.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| File | Microsoft-Windows-Security-Auditing | User accessed file share | 5140 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, ShareName, SubjectUserName, b.SubjectLogonId, IpAddress, IpPort
FROM dataTable b
INNER JOIN (
    SELECT SubjectLogonId
    FROM dataTable
    WHERE LOWER(Channel) = "security"
        AND EventID = 5140
        AND ShareName LIKE '%IPC$'
        AND NOT SubjectUserName LIKE '%$'
    ) a
ON b.SubjectLogonId = a.SubjectLogonId
WHERE LOWER(b.Channel) = 'security'
    AND b.EventID = 5140
    AND b.ShareName LIKE '%C$'
    AND NOT SubjectUserName LIKE '%$'
```

#### Pandas Query

```{code-cell} Ipython3
IPCShareDf = (
df[['@timestamp','Hostname','ShareName','SubjectUserName','SubjectLogonId','AccessMask']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 5140)
    & (df['ShareName'].str.contains('.*IPC.*', regex=True))
    & (~df['SubjectUserName'].str.endswith('$', na=False))
]
)

CShareDf = (
df[['@timestamp','Hostname','ShareName','SubjectUserName','SubjectLogonId','AccessMask']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 5140)
    & (df['ShareName'].str.endswith('\\C$', na=False))
    & (~df['SubjectUserName'].str.endswith('$', na=False))
]
)

(
pd.merge(IPCShareDf, CShareDf,
    on = 'SubjectLogonId', how = 'inner')
)
```

### Analytic III

Look for non-system accounts SMB accessing a file with write (0x2) access mask via administrative share (i.e C$).

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| File | Microsoft-Windows-Security-Auditing | User accessed File | 5145 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, ShareName, SubjectUserName, SubjectLogonId, IpAddress, IpPort, RelativeTargetName
FROM dataTable
WHERE LOWER(Channel) = "security"
    AND EventID = 5145
    AND ShareName LIKE '%C$'
    AND NOT SubjectUserName LIKE '%$'
    AND AccessMask = '0x2'
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','ShareName','SubjectUserName','SubjectLogonId','IpAddress','IpPort','RelativeTargetName']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 5145)
    & (df['AccessMask'] == '0x2')
    & (df['ShareName'].str.endswith('\\C$', na=False))
    & (~df['SubjectUserName'].str.endswith('$', na=False))
]
)
```

### Analytic IV

Look for non-system accounts SMB connecting (Tree Connect) to an IPC$ Share and administrative shares (i.e C$) and accessing/creating a file with write (0x2) access mask with the same logon session ID.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| File | Microsoft-Windows-Security-Auditing | User accessed file share | 5140 |
| File | Microsoft-Windows-Security-Auditing | User accessed File | 5145 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, ShareName, SubjectUserName, d.SubjectLogonId, IpAddress, IpPort, RelativeTargetName
FROM dataTable d
INNER JOIN (
    SELECT b.SubjectLogonId
    FROM dataTable b
    INNER JOIN (
        SELECT SubjectLogonId
        FROM dataTable
        WHERE LOWER(Channel) = "security"
            AND EventID = 5140
            AND ShareName LIKE '%IPC$'
            AND NOT SubjectUserName LIKE '%$'
    ) a
    ON b.SubjectLogonId = a.SubjectLogonId
    WHERE LOWER(b.Channel) = 'security'
        AND b.EventID = 5140
        AND b.ShareName LIKE '%C$'
) c
ON d.SubjectLogonId = c.SubjectLogonId
WHERE LOWER(d.Channel) = 'security'
    AND d.EventID = 5145
    AND d.ShareName LIKE '%C$'
    AND d.AccessMask = '0x2'
```

#### Pandas Query

```{code-cell} Ipython3
IPCShareDf = (
df[['@timestamp','Hostname','ShareName','SubjectUserName','SubjectLogonId','AccessMask']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 5140)
    & (df['ShareName'].str.contains('.*IPC.*', regex=True))
    & (~df['SubjectUserName'].str.endswith('$', na=False))
]
)

CShareDf = (
df[['@timestamp','Hostname','ShareName','SubjectUserName','SubjectLogonId','AccessMask']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 5140)
    & (df['ShareName'].str.endswith('\\C$', na=False))
]
)


firstJoinDf = (
pd.merge(IPCShareDf, CShareDf,
    on = 'SubjectLogonId', how = 'inner')
)

fileAccessedDf = (
df[['@timestamp','Hostname','ShareName','SubjectUserName','SubjectLogonId','IpAddress','IpPort','RelativeTargetName']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 5145)
    & (df['AccessMask'] == '0x2')
    & (df['ShareName'].str.endswith('\\C$', na=False))
]
)

(
pd.merge(firstJoinDf, fileAccessedDf,
    on = 'SubjectLogonId', how = 'inner')
)
```

### Analytic V

Look for files that were accessed over the network with write (0x2) access mask via administrative shares (i.e C$) and that were created by the System process on the target system.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| File | Microsoft-Windows-Security-Auditing | User accessed File | 5145 |
| File | Microsoft-Windows-Sysmon/Operational | Process created File | 11 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, ShareName, SubjectUserName, SubjectLogonId, IpAddress, IpPort, RelativeTargetName
FROM dataTable b
INNER JOIN (
    SELECT LOWER(REVERSE(SPLIT(TargetFilename, '\'))[0]) as TargetFilename
    FROM dataTable
    WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
        AND Image = 'System'
        AND EventID = 11
) a
ON LOWER(REVERSE(SPLIT(RelativeTargetName, '\'))[0]) = a.TargetFilename
WHERE LOWER(b.Channel) = 'security'
    AND b.EventID = 5145
    AND b.AccessMask = '0x2'
```

#### Pandas Query

```{code-cell} Ipython3
fileAccessedDf = (
df[['@timestamp','Hostname','ShareName','SubjectUserName','SubjectLogonId','IpAddress','IpPort','RelativeTargetName']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 5145)
    & (df['AccessMask'] == '0x2')
]
)

fileAccessedDf['Filename'] = fileAccessedDf['RelativeTargetName'].str.split('\\').str[-1]

fileCreateDf = (
df[['@timestamp','Hostname','Image','TargetFilename']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 11)
    & (df['Image'].str.lower() == 'system')
]
)

fileCreateDf['Filename'] = fileCreateDf['TargetFilename'].str.split('\\').str[-1]

(
pd.merge(fileAccessedDf, fileCreateDf,
    on = 'Filename', how = 'inner')
)
```

## Known Bypasses

## False Positives

## Hunter Notes

* Baseline your environment to identify normal activity. Document all accounts creating files over the network via administrative shares.

## References
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/8341356c-ede3-4e1c-a056-3de91473bde6
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997
