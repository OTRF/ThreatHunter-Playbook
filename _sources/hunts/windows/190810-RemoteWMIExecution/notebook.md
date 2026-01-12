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

# WMI Win32_Process Class and Create Method for Remote Execution

## Hypothesis

Adversaries might be leveraging WMI Win32_Process class and method Create to execute code remotely across my environment

## Technical Context

WMI is the Microsoft implementation of the Web-Based Enterprise Management (WBEM) and Common Information Model (CIM).
Both standards aim to provide an industry-agnostic means of collecting and transmitting information related to any managed component in an enterprise.
An example of a managed component in WMI would be a running process, registry key, installed service, file information, etc.
At a high level, Microsoft's implementation of these standards can be summarized as follows > Managed Components Managed components are represented as WMI objects â€” class instances representing highly structured operating system data. Microsoft provides a wealth of WMI objects that communicate information related to the operating system. E.g. Win32_Process, Win32_Service, AntiVirusProduct, Win32_StartupCommand, etc.

## Offensive Tradecraft

One well known lateral movement technique is performed via the WMI object â€” class Win32_Process and its method Create.
This is because the Create method allows a user to create a process either locally or remotely.
One thing to notice is that when the Create method is used on a remote system, the method is run under a host process named "Wmiprvse.exe".

The process WmiprvSE.exe is what spawns the process defined in the CommandLine parameter of the Create method. Therefore, the new process created remotely will have Wmiprvse.exe as a parent. WmiprvSE.exe is a DCOM server and it is spawned underneath the DCOM service host svchost.exe with the following parameters C:\WINDOWS\system32\svchost.exe -k DcomLaunch -p.
From a logon session perspective, on the target, WmiprvSE.exe is spawned in a different logon session by the DCOM service host. However, whatever is executed by WmiprvSE.exe occurs on the new network type (3) logon session created by the user that authenticated from the network.

Additional Reading
* https://github.com/OTRF/ThreatHunter-Playbook/tree/master/docs/library/windows/logon_session.md

## Pre-Recorded Security Datasets

| Metadata  |    Value  |
|:----------|:----------|
| docs      | https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-200921001437.html        |
| link      | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip  |

### Download Dataset

```{code-cell} ipython3
import requests
from zipfile import ZipFile
from io import BytesIO

url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod.zip'
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

Look for wmiprvse.exe spawning processes that are part of non-system account sessions.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Security-Auditing | Process created Process | 4688 |
| Process | Microsoft-Windows-Security-Auditing | User created Process | 4688 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, SubjectUserName, TargetUserName, NewProcessName, CommandLine
FROM dataTable
WHERE LOWER(Channel) = "security"
    AND EventID = 4688
    AND lower(ParentProcessName) LIKE "%wmiprvse.exe"
    AND NOT TargetLogonId = "0x3e7"
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','SubjectUserName','TargetUserName','TargetLogonId','NewProcessName','CommandLine']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4688)
    & (df['ParentProcessName'].str.lower().str.endswith('wmiprvse.exe', na=False))
    & (df['TargetLogonId'] != '0x3e7')
]
.head()
)
```

### Analytic II

Look for wmiprvse.exe spawning processes that are part of non-system account sessions.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Sysmon/Operational | Process created Process | 1 |
| Process | Microsoft-Windows-Sysmon/Operational | User created Process | 1 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, User, Image, CommandLine
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND lower(ParentImage) LIKE "%wmiprvse.exe"
    AND NOT LogonId = "0x3e7"
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','User','Image','CommandLine']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 1)
    & (df['ParentImage'].str.lower().str.endswith('wmiprvse.exe', na=False))
    & (df['LogonId'] != '0x3e7')
]
.head()
)
```

### Analytic III

Look for non-system accounts leveraging WMI over the netwotk to execute code.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Process | Microsoft-Windows-Security-Auditing | Process created Process | 4688 |
| Process | Microsoft-Windows-Security-Auditing | User created Process | 4688 |
| Authentication log | Microsoft-Windows-Security-Auditing | User authenticated Host | 4624 |

#### Logic

```{code-block}
SELECT o.`@timestamp`, o.Hostname, o.SubjectUserName, o.TargetUserName, o.NewProcessName, o.CommandLine, a.IpAddress
FROM dataTable o
INNER JOIN (
    SELECT Hostname,TargetUserName,TargetLogonId,IpAddress
    FROM dataTable
    WHERE LOWER(Channel) = "security"
        AND EventID = 4624
        AND LogonType = 3
        AND NOT TargetUserName LIKE "%$"
    ) a
ON o.TargetLogonId = a.TargetLogonId
WHERE LOWER(o.Channel) = "security"
    AND o.EventID = 4688
    AND lower(o.ParentProcessName) LIKE "%wmiprvse.exe"
    AND NOT o.TargetLogonId = "0x3e7"
```

#### Pandas Query

```{code-cell} Ipython3
processCreateDf = (
df[['@timestamp','Hostname','SubjectUserName','TargetUserName','TargetLogonId','NewProcessName','CommandLine','IpAddress']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4688)
    & (df['ParentProcessName'].str.lower().str.endswith('wmiprvse.exe', na=False))
    & (df['TargetLogonId'] != '0x3e7')
]
.head()
)

networkLogonDf = (
df[['@timestamp', 'Hostname', 'TargetUserName', 'TargetLogonId', 'IpAddress']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4624)
    & (df['LogonType'] == 3)
    & (~df['SubjectUserName'].str.endswith('.*$', na=False))
]
)

(
pd.merge(processCreateDf, networkLogonDf,
    on = 'TargetLogonId', how = 'inner')
)
```

## Known Bypasses

## False Positives

## Hunter Notes

* Stack the child processes of wmiprvse.exe in your environment. This is very helpful to reduce the number of false positive and understand your environment. You can categorize the data returned by business unit.
* Look for wmiprvse.exe spawning new processes that are part of a network type logon session.
* Enrich events with Network Logon events (4624 - Logon Type 3)

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_wmiprvse_spawning_process.yml |
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/sysmon_wmi_module_load.yml |

## References
* https://posts.specterops.io/threat-hunting-with-jupyter-notebooks-part-4-sql-join-via-apache-sparksql-6630928c931e
* https://posts.specterops.io/real-time-sysmon-processing-via-ksql-and-helk-part-3-basic-use-case-8fbf383cb54f
