# Remote Service creation

## Metadata


|               |    |
|:--------------|:---|
| id            | WIN-190815181010 |
| author        | Roberto Rodriguez @Cyb3rWard0g |
| creation date | 2019/08/15 |
| platform      | Windows |
| playbook link | WIN-190813181020 |
        

## Technical Description
Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager. This can be done by by adversaries creating a new service.
Adversaries can create services remotely to execute code and move lateraly across the environment.

## Hypothesis
Adversaries might be creating new services remotely to execute code and move laterally in my environment

## Analytics

### Initialize Analytics Engine

from openhunt.mordorutils import *
spark = get_spark()

### Download & Process Mordor File

mordor_file = "https://raw.githubusercontent.com/hunters-forge/mordor/master/datasets/small/windows/execution/empire_invoke_psexec.tar.gz"
registerMordorSQLTable(spark, mordor_file, "mordorTable")

### Analytic I


| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| Low       | ['Security']          | Look for new services being created in your environment under a network logon session (3). That is a sign that the service creation was performed from another endpoint in the environment            |
            

df = spark.sql(
    '''
SELECT o.`@timestamp`, o.computer_name, o.SubjectUserName, o.SubjectUserName, o.ServiceName, a.IpAddress
FROM mordorTable o
INNER JOIN (
    SELECT computer_name,TargetUserName,TargetLogonId,IpAddress
    FROM mordorTable
    WHERE channel = "Security"
        AND LogonType = 3
        AND IpAddress is not null
        AND NOT TargetUserName LIKE "%$"
    ) a
ON o.SubjectLogonId = a.TargetLogonId
WHERE o.channel = "Security"
    AND o.event_id = 4697
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