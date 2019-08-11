# Kerberoasting

An adversary can use domain credentials captured on any user to request Kerberos service tickets for accounts that are associated with the SPN records in Active Directory (AD). The service tickets are signed with the targeted user's NTLM hash, which can then be cracked offline. 

## Technique Variations Table

| Sub-techinque | Author | Updated |
| ----------- | ------- | --------- | 
| [kerberoast](kerberoasting.md) | Jonathan Johnson [@jsecurity101](https://twitter.com/jsecurity101) | 2019-07-25200422 |