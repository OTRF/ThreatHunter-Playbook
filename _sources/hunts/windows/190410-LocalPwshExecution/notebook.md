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

# Local PowerShell Execution

## Hypothesis

Adversaries might be leveraging PowerShell to execute code within my environment

## Technical Context

## Offensive Tradecraft

Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.
Therefore, it is important to understand the basic artifacts left when PowerShell is used in your environment.

## Pre-Recorded Security Datasets

| Metadata  |    Value  |
|:----------|:----------|
| docs      | https://securitydatasets.com/notebooks/atomic/windows/execution/SDWIN-190518182022.html        |
| link      | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip  |

### Download Dataset

```{code-cell} ipython3
import requests
from zipfile import ZipFile
from io import BytesIO

url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip'
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

Within the classic PowerShell log, event ID 400 indicates when a new PowerShell host process has started. You can filter on powershell.exe as a host application if you want to or leave it without a filter to capture every single PowerShell host.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Powershell | Windows PowerShell | Application host started | 400 |
| Powershell | Microsoft-Windows-PowerShell/Operational | User started Application host | 4103 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname
FROM dataTable
WHERE (Channel = "Microsoft-Windows-PowerShell/Operational" OR Channel = "Windows PowerShell")
    AND (EventID = 400 OR EventID = 4103)
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname']]

[((df['Channel'] == 'Windows PowerShell') | (df['Channel'] == 'Microsoft-Windows-PowerShell/Operational'))
    & (
      (df['EventID'] == 400)
      | (df['EventID'] == 4103)
    )
]
.head()
)
```

### Analytic II

Look for non-interactive powershell session might be a sign of PowerShell being executed by another application in the background.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Security-Auditing | Process created Process | 4688 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, NewProcessName, ParentProcessName
FROM dataTable
WHERE LOWER(Channel) = "security"
    AND EventID = 4688
    AND NewProcessName LIKE "%powershell.exe"
    AND NOT ParentProcessName LIKE "%explorer.exe"
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','NewProcessName','ParentProcessName']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4688)
    & (df['NewProcessName'].str.lower().str.endswith('powershell.exe', na=False))
    & (~df['ParentProcessName'].str.lower().str.endswith('explorer.exe', na=False))
]
.head()
)
```

### Analytic III

Look for non-interactive powershell session might be a sign of PowerShell being executed by another application in the background.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process created Process | 1 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, Image, ParentImage
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND Image LIKE "%powershell.exe"
    AND NOT ParentImage LIKE "%explorer.exe"
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','Image','ParentImage']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 1)
    & (df['Image'].str.lower().str.endswith('powershell.exe', na=False))
    & (~df['ParentImage'].str.lower().str.endswith('explorer.exe', na=False))
]
.head()
)
```

### Analytic IV

Monitor for processes loading PowerShell DLL `*system.management.automation*`.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Module | Microsoft-Windows-Sysmon/Operational | Process loaded Dll | 7 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, Image, ImageLoaded
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 7
    AND (lower(Description) = "system.management.automation" OR lower(ImageLoaded) LIKE "%system.management.automation%")
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','Image','ImageLoaded']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 7)
    & (
        (df['Description'].str.lower() == 'system.management.automation')
        | (df['ImageLoaded'].str.lower().str.contains('.*system.management.automation.*', regex=True))
    )
]
.head()
)
```

### Analytic V

Monitoring for PSHost* pipes is another interesting way to find PowerShell execution.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Named Pipe | Microsoft-Windows-Sysmon/Operational | Process created Pipe | 17 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, Image, PipeName
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 17
    AND lower(PipeName) LIKE "\\\\pshost%"
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','Image','PipeName']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 17)
    & (df['PipeName'].str.lower().str.startswith('\pshost', na=False))
]
.head()
)
```

### Analytic VI

The `PowerShell Named Pipe IPC` event will indicate the name of the PowerShell AppDomain that started. Sign of PowerShell execution.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Powershell | Microsoft-Windows-PowerShell/Operational | Application domain started | 53504 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, Message
FROM dataTable
WHERE Channel = "Microsoft-Windows-PowerShell/Operational"
    AND EventID = 53504
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','Message']]

[(df['Channel'] == 'Microsoft-Windows-PowerShell/Operational')
    & (df['EventID'] == 53504)
]
.head()
)
```

## Known Bypasses

## False Positives



## Hunter Notes

* Explore the data produced in your environment with the analytics above and document what normal looks like from a PowerShell perspective.
* If execution of PowerShell happens all the time in your environment, I suggest to categorize the data you collect by business unit to build profiles and be able to filter out potential noise.
* You can also stack the values of the command line arguments being used. You can hash the command line arguments too and stack the values.

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/sysmon_powershell_execution_pipe.yml |
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_non_interactive_powershell.yml |

## References
* https://github.com/darkoperator/Presentations/blob/master/PSConfEU%202019%20Tracking%20PowerShell%20Usage.pdf
* https://posts.specterops.io/abusing-powershell-desired-state-configuration-for-lateral-movement-ca42ddbe6f06
