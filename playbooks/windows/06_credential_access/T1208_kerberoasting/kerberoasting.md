# Kerberoast

## Playbook Tags

**Author:** Jonathan Johnson [@jsecurity101](https://twitter.com/jsecurity101)


## ATT&CK Tags

**Tactics:** Credential Access

**Techniques:** Kerberoasting (T1208)

## Applies To

## Techinical Description


## Hypothesis

Adversaries might attempt to pull the NTLM hash of a user by using captured domain credentials to request Kerberos TGS tickets for accounts that are associated with a Service Principal Name (SPN).

## Permission Required

Domain User

## Attack Simulation Dataset

| RT Platform  | Dataset | Author |
|---------|---------|---------|
| Empire | [empire_kerberoast](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/credential_access/kerberoasting_T1208/empire_kerberoast.md) | Jonathan Johnson [@jsecurity101](https://twitter.com/jsecurity101) |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|-----|
| [4769](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4769.md) | A Kerberos service ticket was requested | Microsoft-Windows-Security-Auditing | Audit Kerberos Service Ticket Operations |  | Windows Event Logs |


## Analytic(s) Relationships

| Data Object | Relationship | Data Object | Event ID |
|--------|---------|-------|--------|
|  user | requested | service ticket | 4769 |

## Data Analytics

| FP Rate | Source | Analytic Platform | Analytic Logic | Description |
|--------|---------|---------|---------|---------|
| Medium | Security | Kibana | `event_id:4769 AND ticket_encryption_type_value: "RC4-HMAC" AND NOT (user_name: *$ AND service_ticket_name: krbtgt AND service_ticket_name:*$)` | Pulls events that correlate with `A service ticket was requested`, that were requested in the encryption type: RC4. Filters if the service ticket was granted. Filters out any machine account ($) that requested the service ticket. Lastly, filters out any `requested` service ticket names that are `krbtgt` or a machine account ($). |
| Medium | Security | Splunk | `index=wineventlog EventCode=4769 Service_Name!="krbtgt" Service_Name!="*$" Failure_Code ="0x0"  Ticket_Encryption_Type="0x17" Account_Name!="*$*"` | Pulls events that correlate with `A service ticket was requested`, that were requested in the encryption type: RC4. Filters if the service ticket was granted. Filters out any machine account ($) that requested the service ticket. Lastly, filters out any `requested` service ticket names that are `krbtgt` or a machine account ($).| 
| Medium | Security | Jupyter Notebooks + Apache Spark |SELECT event_id, user_name, ticket_encryption_type_value, service_ticket_name FROM security_events WHERE event_id = 4769 AND ticket_encryption_type_value = "RC4-HMAC" AND NOT user_name LIKE "%$" AND NOT( service_ticket_name LIKE "%$" AND service_ticket_name = "krbtgt" )

**Note**: For `Account_Name!=*$*` enter your personalized domain so that the query is faster. Example: `Account_Name!="*$@domain.com`

## Potential False Positives

* Anytime a user wants access to a service, a service ticket is requested. Meaning, service tickets are requested very often in enviroments. This makes this attack hard to hunt for. 

## Detection Blind Spots

* Advesary is pulling tickets in a different encryption format. (Ex: AES256_CTS_HMAC_SHA1_96)

## Hunter Notes

* An adversary can use the captured users domain credentials to request Kerberos TGS tickets for accounts that are associated with an SPN. This ticket can be requested in a specific format (RC4), so when taking it offline it is easier to crack. I have noticed however when specifying that the account requesting the service ticket isn't a `machine($)` account, the service ticket name they are trying to get access to typeicaly isnt going to be the `krbtgt` account, the failure code is `0x0` - ticket was granted, and the ticket encryption is typically requested in `RC4` format - this either gets us to the account that the advesary was using or limits down the results to where you can pick out the false positives to find the advesary easier. In a real enviroment this would have to be tailored to fit the enviroments paramenters and needs to better specifiy th query, but this sets a good baseline. 
* Another good alternative, is to see how many service tickets were pulled in a given time frame. Alot of advesaries won't do `targeted` attacks. They will just pull as many as they can. 
* Setting a `canary` account is good as well. This is a fake account that is meant to give some insight on attacks. It isn't linked to any services, so if this `canary` account is requested to give a service ticket, we know that an advesary is trying to pull these down. 

## References
* Will Schroeder (@harmj0y)
* https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/
* https://jsecurity101.com/2019/IOC-differences-between-Kerberoasting-and-AsRep-Roasting/
* https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/
* https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4769.md
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
