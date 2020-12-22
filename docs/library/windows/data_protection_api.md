# Data Protection API

Starting with Microsoft® Windows® 2000, the operating system began to provide a data protection application-programming interface (API). This Data Protection API (DPAPI) is a pair of function calls  `(CryptProtectData / CryptUnprotectData)` that provide operating system-level data protection services to user and system processes. By operating system-level, we mean a service that is provided by the operating system itself and does not require any additional libraries. By data protection, we mean a service that provides confidentiality of data by using encryption. Because data protection is part of the operating system, every application can now secure data without needing any specific cryptographic code other than the necessary function calls to DPAPI. 

## Password Based Data Protection Service

DPAPI is a password-based data protection service. It requires a password to provide protection. The drawback, of course, is that all protection provided by DPAPI rests on the password provided. Because DPAPI is focused on providing protection for users and requires a password to provide this protection, it logically uses the user's logon password for protection. Because DPAPI requires a password to provide protection, the logical step is for DPAPI to use a user's logon password, which it does, in a way. DPAPI actually uses the user's logon credential. A small drawback to using the logon password is that all applications running under the same user can access any protected data that they know about.

DPAPI initially generates a strong key called a MasterKey, which is protected by the user's password. DPAPI uses a standard cryptographic process called Password-Based Key Derivation to generate a key from the password. This password-derived key is then used with Triple-DES to encrypt the MasterKey, which is finally stored in the user's profile directory.

The MasterKey, however, is not used explicitly to protect the data. Instead, a symmetric session key is generated based on the MasterKey, some random data, and any additional entropy, if an application chooses to supply it. It is this session key that is used to protect the data. The session key is never stored. Instead, DPAPI stores the random data it used to generate the key in the opaque data BLOB. When the data BLOB is passed back in to DPAPI, the random data is used to re-derive the key and unprotect the data.

## Encrypt / Decrypt

Applications either pass plaintext data to DPAPI and receive an opaque protected data BLOB back, or pass the protected data BLOB to DPAPI and receive the plaintext data back.

The protected data BLOB is an opaque structure because, in addition to the encrypted data, it also contains data to allow DPAPI to unprotect it. Being opaque, application developers do not need to parse or understand the format at all. An important point to remember is that DPAPI merely applies cryptographic protection to the data. It does not store any of the protected data; therefore applications calling DPAPI must implement their own storage of the protected data.

## Calling DPAPI Functions

* When an application calls one of the DPAPI functions, the functions make a local RPC call to the Local Security Authority (LSA).
    * The LSA is a system process that starts on boot and runs until the computer is shut down. These local RPC calls never traverse the network, so all data remains on the local machine.
* The endpoints of these RPC calls then call DPAPI private functions to protect or unprotect the data.
* These functions then call back into CryptoAPI, by using Crypt32.dll, for the actual encryption or decryption of the data in the security context of the LSA.
* The functions run in the security context of the LSA so that security audits can be generated.

## Master Key

DPAPI generates a strong key called the MasterKey. Calling the MasterKey a key isn't really correct because it is never used in any explicit encryption or decryption functions. The MasterKey is more accurately a strong secret: strong because it is 512 bits of random data, and secret because it is used, with some additional data, to generate an actual symmetric session key.

To protect this secret, DPAPI uses the Password-Based Key Derivation Function, PBKDF2, described in PKCS #5.

* First, DPAPI takes the user's password and passes it through SHA-1 to get a password hash.
* Next, the password hash is provided to the PBKDF2 function, along with sixteen random bytes for a salt and an iteration count.
* The PBKDF2 function calls an additional function a number of times, specified by the iteration count, to derive a key from the given data. DPAPI uses SHA-1 for that underlying function.

## Session Key

The session key is the real symmetric key that is used for encrypting and decrypting the application data. DPAPI uses a simple process to derive the session key.

## Recovery Key

The recovery key is generated when a user chooses to create a Password Reset Disk (PRD) from the user's Control Panel.

* First, DPAPI generates a 2048-bit RSA public/private key pair, which is the recovery key.
* The current password is then encrypted with the public key and stored in the user's profile, while the private key is stored to the PRD, which can actually be any removable media, and then removed from memory.
* The private key is only stored on the PRD, and nowhere else, so it is important for a user to keep the PRD in a safe place.

## Master Keys Expiration

For security reasons, MasterKeys will expire, which means that after a period of time (the hard-coded value being `three months`), a new MasterKey is generated and protected in the same manner. This expiration prevents an attacker from compromising a single MasterKey and accessing all of a user's protected data.

You are probably wondering how an application can unprotect data that was protected under a MasterKey that has expired, because the session key is derived from the MasterKey, right? Well the answer involves a two-step process. First, DPAPI does not delete any expired MasterKeys. Instead, they are kept forever in the user's profile directory, protected by the user's password. Second, it stores the Globally Unique Identifier (GUID) of the MasterKey used to protect the data in the opaque data BLOB that is returned to applications. When the data BLOB is passed back in to DPAPI, the MasterKey that corresponds to the GUID is used to unprotect the data.

## Master Keys and Users Password Change

First, DPAPI hooks into the password-changing module and when a user's password is changed, all MasterKeys are re-encrypted under the new password. Second, the system keeps a "Credential History" file in the user's profile directory. When a user changes his or her password, the old password is added to the top of this file and then the file is encrypted by the new password. If necessary, DPAPI will use the current password to decrypt the "Credential History" file and try the old password to decrypt the MasterKey. If this fails, the old password is used to again decrypt the "Credential History" file and the next previous password is then tried. This continues until the MasterKey is successfully decrypted.

## Key Backup and Restoration in DPAPI

When a computer is a member of a domain, DPAPI has a backup mechanism to allow unprotection of the data. When a Master Key is generated, DPAPI communicates with a domain controller. Domain controllers have a domain-wide public/private key pair, associated solely with DPAPI. The local DPAPI client gets the domain controller public key from a domain controller by using a mutually authenticated and privacy protected RPC call. The client encrypts the Master Key with the domain controller public key. It then stores this backup Master Key along with the Master Key protected by the user's password.

Periodically, a domain-joined machine will try to send an RPC request to a domain controller to back up the user’s master key so that the user can recover secrets in case his or her password has to be reset. Although the user's keys are stored in the user profile, a domain controller must be contacted to encrypt the master key with a domain recovery key.

When DPAPI is used in an Active Directory domain environment, two copies of the master key are created and updated whenever an operation is performed on the master key. The first copy is protected by the user password as described earlier in this article. The second copy is encrypted with a public key that is associated with the domain controllers in the domain. The private key that is associated with this public key is known to all of the Windows 2000 and later domain controllers. Windows 2000 domain controllers use a symmetric key to encrypt and decrypt the second copy of the master key. 

While unprotecting data, if DPAPI cannot use the MasterKey protected by the user's password, it sends the backup MasterKey to a Domain Controller by using a mutually authenticated and privacy protected RPC call. The Domain Controller then decrypts the MasterKey with its private key and sends it back to the client by using the same protected RPC call. This protected RPC call is used to ensure that no one listening on the network can get the MasterKey.

## DPAPI Secrets

### User

* Windows “Credentials” (like saved RDP creds)
* Windows Vaults
* Saved IE and Chrome logins/cookies
* Remote Desktop Connection Manager files with passwords
* Dropbox syncs

### System:

* Scheduled tasks
* Azure sync accounts
* Wifi passwords

## References

* https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection
* https://support.microsoft.com/en-us/help/309408/how-to-troubleshoot-the-data-protection-api-dpapi
* https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)
