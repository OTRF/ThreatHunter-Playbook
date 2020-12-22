# Security Account Manager Remote Protocol (SAMRP)

Accounts are always created relative to an issuing authority. In Windows, the issuing authority is referred to as a domain. A domain can be either a local domain or extend across a network. Domains store information about their accounts in an account database. Windows uses Active Directory as the account database in domain-based environments, whereas in environments that are not domain-based, it uses the security account manager (SAM) built-in database as the account database.

## Security Account Manager Remote Protocol (SAMRP) Client-To-Server (C)

The Security Account Manager (SAM) Remote Protocol (Client-to-Server) depends on the RPC protocol (uses RPC as a transport), and provides management functionality for an account store or directory containing users and groups. The goal of this protocol is to enable IT administrators and end users to manage users, groups, and computers. This protocol achieves its goal by enabling the creation, reading, updating, and deleting of security principal information. These security principals could be in any account store. Windows implements this protocol, for example, in a directory service (Active Directory) and in a computer-local security account database known as the Security Account Manager (SAM) database.

This protocol follows two perspectives when understanding and implementing this protocol:

## Object-based perspective

The object-based perspective shows that the protocol exposes five main object abstractions: a server object, a domain object, a group object, an alias object (an "alias" being a type of group), and a user object. A client obtains a "handle" (an RPC context handle) to one of these objects and then performs one or more actions on the object.

You can find the list of methods that operate on each of the respective object types in [here](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/8aaff2f7-1edd-41a0-ab58-4807ac6124c5)

## Method Based Perspective

The method-based perspective is used to show a common set of operations for each object type. The operations fall into patterns. A list of the patterns and associated methods, along with a description of each pattern, is available [here](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/d7b62596-4a46-4556-92dc-3aba6d517907). A brief description is available below:

| Pattern | Description |
|---------|-------------|
| Open | This pattern returns an RPC context handle that references a specific object type. A client uses this pattern by specifying a specific access for the handle in the request, and using the returned handle to call other methods that require the returned handle along with the associated access. |
| Enumerate | This pattern allows a client to obtain a complete list of all objects of a certain type (domain, group, alias, or user). |
| Selective Enumerate | This pattern allows a client to obtain a partial list of objects based on the name of the objects. These methods, for example, allow a client to obtain a bounded number of objects from a virtual list of objects sorted alphabetically by name starting with a client-specified prefix, such as "Chr". |
| Create | This pattern allows specified objects to be created. A handle to the newly created object is returned. |
| Query | This pattern allows specified attributes of an object to be returned. The client specifies which attributes to return by using an "information level". The information level is an enumeration that the server understands and translates into a specific structure to return; the structure contains the attributes indicated by the information level. |
| Set | This pattern allows specified object attributes to be set. The client indicates the attributes that are to be updated by specifying an "information level". Similar to the query pattern of methods, the information level specifies the attributes that are being sent in the request. |
| Delete | This pattern allows a client to delete a specified object. |
| Membership | This pattern allows a client to add to, remove from, or query the membership list for either a group or an alias object. |
| Membership-Of | This pattern allows a client to obtain the groups or aliases that a user or collection of security identifiers (SIDs) is a member of. |
| Change Password | This pattern allows a client to change a password on a user object. The client provides the current password and new password, and the server verifies that the client-presented current password matches the server-persisted current password for the user. If there is a match, the new password is persisted. |
| Lookup | This pattern allows a client to translate between a relative identifier (RID) or SID, and a user-friendly display name (the name of the object). |
| Security | This pattern allows a client to specify or query access control with a granularity of individual objects. |
| Miscellaneous | The following methods do not fall into a general pattern. |

## Transport

* This protocol uses UUID 12345778-1234-ABCD-EF00-0123456789AC to identify the RPC interface
* This protocol uses the following RPC protocol sequences:
    * RPC over SMB ( This protocol uses the pipe name "\PIPE\samr" for the endpoint name )
    * RPC over TCP ( This protocol uses RPC dynamic endpoints ) 

## Protocol Details

### Server

* This protocol enables create, read, update, and delete semantics over an account domain. Five abstract objects are exposed through this protocol: server, domain, group, alias, and user. User, group, and alias objects can be created and deleted; all objects can be updated and read.
* For methods that accept a context handle, the security model is a handle-based security model. A client obtains a handle with a client-specified access for that handle. The handle can then be used for operations that require the granted access.

### Client

* The client MUST create a secure RPC session such that the server can identify and determine the authorization for the client.

## Abusing Remote Calls to SAM

The SAMRPC protocol makes it possible for a low privileged user to query a machine on a network for data. For example, a user can use SAMRPC to enumerate users, including privileged accounts such as local or domain administrators, or to enumerate groups and group memberships from the local SAM and Active Directory. This information can provide important context and serve as a starting point for an attacker to compromise a domain or networking environment.

By default, the SAM can be accessed remotely (via SAMR) by any authenticated user, including network connected users, which effectively means that any domain user is able to access it. Windows 10 had introduced an option to control the remote access to the SAM, through a specific registry value. On Windows Anniversary update (Windows 10 Version 1607) the default permissions were changed to allow remote access only to administrators. An accompanying Group Policy setting was added, which gives a user-friendly interface to alter these default permissions.

There are corresponding events that indicate when remote calls to the SAM are restricted, what accounts attempted to read from the SAM database, and more [here](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls#related-events).

## References

* https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls#audit-only-mode
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/8aaff2f7-1edd-41a0-ab58-4807ac6124c5
* https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls
