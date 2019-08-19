### Kerberos and the Kerberos ticketing system:
A simple brief and explanation of the `Kerberos Authentication Protocol`:

Kerberos is the primary authentication protocol used in Windows Active Directory domains. The Kerberos protocol uses `tickets` to authenticate and/or authorize domain joined users. 

Inside of each domain, every Domain Controller runs a service known as the `Kerberos Distribution Center` service or `KDC.` This service handles all of the ticket requests done within Kerberos. The KDC uses an account known as `KRBTGT` to sign all Kerberos tickets within the domain. When a user initally `logs in` or `authenticates` it will request a `ticket granting ticket(TGT)`. If the authentication is successful it will recieve the `TGT` ticket. The `TGT` ticket is encrypted/signed with the `KRBTGT` hash.

If a domain user wants access to a service they will present their `TGT` ticket to the `DC` and request a `Service Ticket (TGS)` for the `Service Prinicipal Name (SPN)` of the specific service they want to access. The SPN is used to uniquely identify a Windows Service. Any service implementing Kerberos authentication is required to have a unique SPN registered in with a user or computer account in Active Directory. The encryption keys for the associated user or computer account are what's used to encrypt service tickets sent back to requesting clients.

E.g. if a user wanted to access the file system on `server.domain.com`, they would present their `TGT` to the Domain Controller and request a service ticket for `cifs/server.domain.com`.

### Abusing the Kerberos ticketing system to capture a domain user's credentials:

By the design of Active Directory's Kerberos implementation (and because Kerberos handles authentication, not authorization) any user is able to request a TGS ticket for any SPN. Since the TGS returned for a specific SPN request is encrypted with the hash of the user/computer account with that SPN registered to it, this gives us a piece of information (encrypted with the linked account's encryption keys) that can be cracked by an attacker offline to reveal the account's clear text password. This attack is known as "kerberoasting".

Since computer account passwords are randomized and changed every 30 days, attackers will request crackable service tickets for user accounts with SPNs registered. Attackers also prefer requesting tickets encrypted with the RC4 (NTLM) version of the account's keys, as this encryption version is the easiest to crack. User accounts, by default, use RC4 encryption by default for service ticket encryption.

### Service Tickets

Events are generated any time a service ticket is requested, assuming you have this audit policy enabled. Keep in mind this event will only be generated on the Domain Controller, as this is where the KDC is stored. 

[4769 from the security log channel](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4769.md).

* Account Information: Here you can find the account information of the user or machine account that requested a service ticket
* Service Information: This is where you can see the the Service Name and Service ID that the service ticket is granting access to.  
* Additional Information: Important information here is seeing whether the failure code is `0x0` or not. If the failure code is anything other then `0x0` then the service ticket was not granted. 

### Hunters Notes:
Remember that adversaries willing to perform a Kerberoast, only need any domain accounts credentials. No special privileges are needed. Seeing a user account that usually doesn't have an association with a specific SPN or service is supicious. Along with, if this user is requesting multiple service tickets at once or in a short time span. 


## References
* Will Schroeder (@harmj0y)
* https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/
* https://jsecurity101.com/2019/IOC-differences-between-Kerberoasting-and-AsRep-Roasting/
* https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/
* https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/security/events/event-4769.md
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769