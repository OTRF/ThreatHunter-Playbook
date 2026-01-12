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

# WMI Eventing

## Hypothesis

Adversaries might be leveraging WMI eventing for persistence in my environment.

## Technical Context

WMI is the Microsoft implementation of the Web-Based Enterprise Management (WBEM) and Common Information Model (CIM). Both standards aim to provide an industry-agnostic means of collecting and transmitting information related to any managed component in an enterprise.
An example of a managed component in WMI would be a running process, registry key, installed service, file information, etc.
At a high level, Microsoft implementation of these standards can be summarized as follows > Managed Components Managed components are represented as WMI objects â€” class instances representing highly structured operating system data. Microsoft provides a wealth of WMI objects that communicate information related to the operating system. E.g. Win32_Process, Win32_Service, AntiVirusProduct, Win32_StartupCommand, etc.

## Offensive Tradecraft

From an offensive perspective WMI has the ability to trigger off nearly any conceivable event, making it a good technique for persistence.

Three requirements
* Filter - An action to trigger off of
* Consumer - An action to take upon triggering the filter
* Binding - Registers a FilterConsumer

## Pre-Recorded Security Datasets

| Metadata  |    Value  |
|:----------|:----------|
| docs      | https://securitydatasets.com/notebooks/atomic/windows/persistence/SDWIN-190518184306.html        |
| link      | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user.zip |

### Download Dataset

```{code-cell} ipython3
import requests
from zipfile import ZipFile
from io import BytesIO

url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user.zip'
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

Look for WMI event filters registered.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| WMI object | Microsoft-Windows-Sysmon/Operational | User created Wmi filter | 19 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, User, EventNamespace, Name, Query
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 19
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','User','EventNamespace','Name','Query']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 19)
]
.head()
)
```

### Analytic II

Look for WMI event consumers registered.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| WMI object | Microsoft-Windows-Sysmon/Operational | User created Wmi consumer | 20 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, User, Name, Type, Destination
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 20
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','User','Name','Type','Destination']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 20)
]
.head()
)
```

### Analytic III

Look for WMI consumers binding to filters.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| WMI object | Microsoft-Windows-Sysmon/Operational | User created Wmi subscription | 21 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, User, Operation, Consumer, Filter
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 21
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','User','Operation','Consumer','Filter']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 21)
]
.head()
)
```

### Analytic IV

Look for events related to the registration of FilterToConsumerBinding.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| WMI object | Microsoft-Windows-WMI-Activity/Operational | Wmi subscription created | 5861 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, Message
FROM dataTable
WHERE Channel = "Microsoft-Windows-WMI-Activity/Operational"
    AND EventID = 5861
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','Message']]

[(df['Channel'] == 'Microsoft-Windows-WMI-Activity/Operational')
    & (df['EventID'] == 5861)
]
.head()
)
```

## Known Bypasses

## False Positives

## Hunter Notes

## References
* https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor.pdf
* https://twitter.com/mattifestation/status/899646620148539397
* https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity
