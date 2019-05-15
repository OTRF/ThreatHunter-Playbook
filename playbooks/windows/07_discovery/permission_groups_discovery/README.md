# Technique: Permission Groups Discovery

Variants available for this technique:

* [users_groups_enumeration](variants/users_groups_enumeration.md)


SAMRPC

The SAMRPC protocol makes it possible for a low privileged user to query a machine on a network for data. For example, a user can use SAMRPC to enumerate users, including privileged accounts such as local or domain administrators, or to enumerate groups and group memberships from the local SAM and Active Directory. This information can provide important context and serve as a starting point for an attacker to compromise a domain or networking environment.

https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls#audit-only-mode