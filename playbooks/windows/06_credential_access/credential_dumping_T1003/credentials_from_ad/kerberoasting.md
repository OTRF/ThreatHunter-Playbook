# Using captured domain credentials to request Kerberos TGS tickets for accounts that are associated with a Service Principal Name (SPN)


## Author

Jonathan Johnson [@jsecurity101](https://twitter.com/jsecurity101)

## Technique ID

T1208

## Hypothesis

Adversaries might attempt to pull the NTLM hash of a user by using captured domain credentials to request Kerberos TGS tickets for accounts that are associated with a Service Principal Name (SPN).

## Attack Knowledge

### Kerberos and the Kerberos ticketing system:
A simple brief and explanation of the `Kerberos Authentication Protocol`:

Kerberos is an authentication protocol that is used primarily when machines are connected through a domain. The Kerberos protocol uses `tickets` to authenticate and/or authorize domain joined users. 

Inside of each domain, every Domain Controller runs a service known as the `Kerberos Distribution Center` service or `KDC.` This service is handles all of the ticket requests done within Kerberos. The KDC uses an account known as `KRBTGT` to sign all Kerberos tickets within the domain. When a user initally `logs in` or `authenticates` it will request a `ticket granting ticket(TGT)`. If the authentication is successful it will recieve the `TGT` ticket. The `TGT` ticket is encrypted/signed with the `KRBTGT` hash.

If a domain user wants access to a service they will present their `TGT` ticket to the `DC` and request a `Service Ticket (TGS)` for the `Service Prinicipal Name (SPN)`. The SPN is used to uniquely identify a Windows Service. Kerberos authentication requires that with each service logon account there must be a SPN associated. This allows a client to request a service authentication without having the actual account name.

Ex: Say a user wanted access to file on a remote system they could request a `TGS` for `cifs/domain.com`.

### Abusing the Kerberos ticketing system to capture a domain user's credentials:

An adversary can use the captured users domain credentials to request Kerberos TGS tickets for accounts that are associated with the SPN records within Active Directory. The TGS tickets are signed with the targeted user or services NTLM hash. This can then be cracked offline to retrieve the clear text password. By default, the tools to automate this process will retrieve the TGS ticket in the encrypted RC4 algorithm. 

### Service Tickets

Events are generated any time a service ticket is requested, assuming you have this audit policy enabled. Keep in mind this event will only be generated on the Domain Controller, as this is where the KDC is stored. 

[4769 from the security log channel](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4769.md).

* Account Information: Here you can find the account information of the user or machine account that requested a service ticket
* Service Information: This is where you can see the the Service Name and Service ID that the service ticket is granting access to.  
* Additional Information: Important information here is seeing whether the failure code is `0x0` or not. If the failure code is anything other then `0x0` then the service ticket was not granted. 

Remember that adversaries willing to perform a Kerberoast, only need any domain accounts credentials. No special privileges are needed. Seeing a user account that usually doesn't have an association with a specific SPN or service is supicious. Along with, if this user is requesting multiple service tickets at once or in a short time span. 

## Attack Emulation Dataset

| RT Platform  | Dataset | Author |
|---------|---------|---------|
| Empire | [empire_kerberoast](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/credential_access/credential_dumping_T1003/credentials_from_ad/empire_kerberoast.md) | Jonathan Johnson [@jsecurity101](https://twitter.com/jsecurity101) |

## Attack Detection Events

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|-----|
| [4769](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4769.md) | A Kerberos service ticket was requested | Microsoft-Windows-Security-Auditing | Audit Kerberos Service Ticket Operations |  | Windows Event Logs |


## Analytic(s) Relationships

| Data Object | Relationship | Data Object | Event ID |
|--------|---------|-------|--------|
|  user | requested | service ticket | 4769 |

## Data Analytics

| Analytic Platform | Analytic Type  | Analytic Logic |
|--------|---------|---------|
| Kibana | Rule | `event_id:4769 AND NOT (service_ticket_name = *$ AND service_ticket_name = krbtgt) AND failure_code = 0x0` |
| Splunk | Rule | `index = wineventlog EventCode = 4769  Account_Name != "*$" AND (Service_Name != "*$" or Service_Name != "krbtgt") AND Failure_Code = 0x0`

## Potential False Positives

* Anytime a user wants access to a service a service ticket is requested. Meaning, service tickets are requested very often in enviroments. This makes this attack hard to hunt for. 

## Hunter Notes

* An adversary can use the captured users domain credentials to request Kerberos TGS tickets for accounts that are associated with an SPN. This ticket can be requested in a specific format (RC4), so when taking it offline it is easier to crack. I have noticed however when specifying that the account requesting the service ticket isn't a `machine($)` account, the `krbtgt` account, and the `failure code` is `0x0` this either gets us to the account that the advesary was using or limits down the results to where you can pick out the false positives to find the advesary easier. 

## References

* https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/
* https://jsecurity101.com/2019/IOC-differences-between-Kerberoasting-and-AsRep-Roasting/
* https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/
* https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4769.md
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
