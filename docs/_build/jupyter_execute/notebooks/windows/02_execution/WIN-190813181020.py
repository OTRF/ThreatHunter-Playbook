# Service Creation

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-190813181020 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2019/08/13 |
| platform      | Windows |
| playbook link |  |
        

## Technical Description
Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager.
This can be done by by adversaries creating a new service.

## Hypothesis
Adversaries might be creating new services to execute code on a compromised endpoint in my environment

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/hunters-forge/mordor/master/datasets/small/windows/lateral_movement/empire_invoke_psexec.zip"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Security']          | Look for new services being created in your environment and stack the values of it            |
            

df = spark.sql(
    '''
SELECT `@timestamp`, computer_name, SubjectUserName ServiceName, ServiceType, ServiceStartType, ServiceAccount
FROM mordorTable
WHERE channel = "Security" AND event_id = 4697
    '''
)
df.show(10,False)

## Detection Blindspots


## Hunter Notes
* If there are a lot of unique services being created in your environment, try to categorize the data based on the bussiness unit.
* Identify the source of unique services being created everyday. I have seen Microsoft applications doing this.
* Stack the values of the service file name associated with the new service.
* Document what users create new services across your environment on a daily basis

## Hunt Output


## References
* https://www.powershellempire.com/?page_id=523