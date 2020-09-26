# Service Creation

## Metadata


|                   |    |
|:------------------|:---|
| collaborators     | ['Roberto Rodriguez @Cyb3rWard0g', 'Jose Rodriguez @Cyb3rPandaH'] |
| creation date     | 2019/08/13 |
| modification date | 2020/09/20 |
| playbook related  | [] |

## Hypothesis
Adversaries might be creating new services to execute code on a compromised endpoint in my environment

## Technical Context
None

## Offensive Tradecraft
Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager.
This can be done by by adversaries creating a new service.

## Mordor Test Data


|           |           |
|:----------|:----------|
| metadata  | https://mordordatasets.com/notebooks/small/windows/08_lateral_movement/SDWIN-190518210652.html        |
| link      | [https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip](https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip)  |

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor Dataset

mordor_file = "https://raw.githubusercontent.com/OTRF/mordor/master/datasets/small/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I
Look for new services being created in your environment and stack the values of it


| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Service | Microsoft-Windows-Security-Auditing | User created Service | 4697 |

df = spark.sql(
'''
SELECT `@timestamp`, Hostname, SubjectUserName ServiceName, ServiceType, ServiceStartType, ServiceAccount
FROM mordorTable
WHERE LOWER(Channel) = "security" AND EventID = 4697
'''
)
df.show(10,False)

## Known Bypasses


| Idea | Playbook |
|:-----|:---------|

## False Positives
None

## Hunter Notes
* If there are a lot of unique services being created in your environment, try to categorize the data based on the bussiness unit.
* Identify the source of unique services being created everyday. I have seen Microsoft applications doing this.
* Stack the values of the service file name associated with the new service.
* Document what users create new services across your environment on a daily basis

## Hunt Output

| Type | Link |
| :----| :----|

## References
* https://www.powershellempire.com/?page_id=523