# Access to Microphone Device

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2020/06/09 |
| modification date | 2020/09/20 |
| playbook related  | [] |

## Hypothesis
Adversaries might be accessing the microphone in endpoints over the network.

## Technical Context
None

## Offensive Tradecraft
An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.
Based on some research from [@svch0st](https://twitter.com/svch0st) you can to determine when and how long a process had access to the microphone of an endpoint by monitoring the following registry key
  * HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\.

## Mordor Test Data


|           |           |
|:----------|:----------|
| metadata  | https://mordordatasets.com/notebooks/small/windows/09_collection/SDWIN-200609225055.html        |
| link      | [https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/collection/host/msf_record_mic.zip](https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/collection/host/msf_record_mic.zip)  |

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor Dataset

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/collection/host/msf_record_mic.zip"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I
Look for any creation or modification of registry keys under HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows Registry | Microsoft-Windows-Sysmon/Operational | Process created Windows registry key | 12 |
| Windows Registry | Microsoft-Windows-Sysmon/Operational | Process modified Windows registry key value | 13 |
| Windows Registry | Microsoft-Windows-Sysmon/Operational | Process modified Windows registry key value | 14 |
| Windows Registry | Microsoft-Windows-Sysmon/Operational | Process modified Windows registry key | 14 |

df = spark.sql(
'''
SELECT EventID, Message
FROM mordorTable
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
  AND EventID IN (12,13,14)
  AND LOWER(TargetObject) RLIKE '.*consentstore\\\\\\\microphone.*'
'''
)
df.show(10,False)

### Analytic II
Look for any creation or modification of registry keys under HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows Registry | Microsoft-Windows-Security-Auditing | Process accessed Windows registry key | 4663 |
| Windows Registry | Microsoft-Windows-Security-Auditing | User accessed Windows registry key | 4663 |
| Windows Registry | Microsoft-Windows-Security-Auditing | Process requested access Windows registry key | 4656 |
| Windows Registry | Microsoft-Windows-Security-Auditing | User requested access Windows registry key | 4656 |
| Windows Registry | Microsoft-Windows-Security-Auditing | Process modified Windows registry key value | 4657 |
| Windows Registry | Microsoft-Windows-Security-Auditing | User modified Windows registry key value | 4657 |

df = spark.sql(
'''
SELECT EventID, Message
FROM mordorTable
WHERE LOWER(Channel) = 'security'
  AND EventID IN (4656,4663,4657)
  AND LOWER(ObjectName) RLIKE '.*consentstore\\\\\\\microphone.*'
'''
)
df.show(10,False)

## Known Bypasses


| Idea | Playbook |
|:-----|:---------|

## False Positives
None

## Hunter Notes
None

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/blob/master/signatures/sigma/sysmon_camera_microphone_access.yml](https://github.com/OTRF/ThreatHunter-Playbook/blob/master/signatures/sigma/sysmon_camera_microphone_access.yml) |
| Sigma Rule | [https://github.com/OTRF/ThreatHunter-Playbook/blob/master/signatures/sigma/win_camera_microphone_access.yml](https://github.com/OTRF/ThreatHunter-Playbook/blob/master/signatures/sigma/win_camera_microphone_access.yml) |

## References
* https://medium.com/@7a616368/can-you-track-processes-accessing-the-camera-and-microphone-7e6885b37072