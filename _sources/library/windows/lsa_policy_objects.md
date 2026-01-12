# LSA Policy Objects

The LSA stores local security policy information in a set of objects. Your application can query or edit the local security policy by accessing these objects.

The set consists of the following four objects:

* `Policy` contains global policy information.
* `TrustedDomain` contains information about a trusted domain.
* `Account` contains information about a user, group, or local group account.
* `Private Data` contains protected information, such as server account passwords. This information is stored as encrypted strings.

## Policy Object

The Policy object is used to control access to the Local Security Authority (LSA) database and contains information that applies to the entire system or establishes defaults for the system. Each system has only one Policy object. This Policy object is created by the LSA when the system starts up, and applications cannot create or destroy it.

## TrustedDomain Object

The TrustedDomain object stores information about a trust relationship with a domain. A TrustedDomain object is created on the trusting system to identify an account within the trusted domain that can be used to submit authentication requests and to perform other operations, such as name and security identifier (SID) translations.

## Account Object

The Account object is used to assign privileges, system access, and special quotas to individual users or to members of local groups or groups.

### Private Data Object

A limited number of private data objects are available on each system for the purpose of storing information in a protected, encrypted, fashion.

Private data objects are provided primarily to support storage of server account passwords. This is useful for servers that run in a specific account. The password of the server account is private data that should be secured but is needed to log the server on.

Private data objects may be general purpose, or they may be one of three specialized types: local, global, and machine.

### Local private data objects (L$)

They can only be read locally from the computer storing the object. Attempting to read them remotely results in a STATUS_ACCESS_DENIED error. Local private data objects have key names that begin with the prefix `L$`. In addition to the local private objects you create, the operating system defines the following local private objects: $machine.acc, SAC, SAI, and SANSC.

### Global private data objects (G$)

They are global in the sense that if they are created on a domain controller, they will be automatically replicated to all domain controllers in that domain. In other words, each domain controller in that domain will have access to the values the global private data object contains. In contrast, global private data objects created on a system that is not a domain controller, as well as nonglobal private data objects, are not replicated. Global private data objects have key names beginning with "G$".

Examples:
* `G$BCKUPKEY_PREFERRED` LSA secret: It contains key pair identifier (16-byte GUID) of object that holds the current modern key
* `G$BCKUPKEY_P` LSA secret: It contains GUID of object that holds the legacy key

### Machine private data objects (M$)

They can be accessed only by the operating system. These objects have key names that begin with "M$".
