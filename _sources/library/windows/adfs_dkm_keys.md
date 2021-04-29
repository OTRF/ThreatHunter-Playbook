# Active Directory Federation Services (ADFS) Distributed Key Manager (DKM) Keys

## ADFS

Active Directory Federation Service (AD FS) enables Federated Identity and Access Management by securely sharing digital identity and entitlements rights across security and enterprise boundaries. AD FS extends the ability to use single sign-on functionality that is available within a single security or enterprise boundary to Internet-facing applications to enable customers, partners, and suppliers a streamlined user experience while accessing the web-based applications of an organization.

## DKM

Distributed Key Manager (DKM) is a client-side functionality that uses a set of secret keys to encrypt and decrypt information. Only members of a specific security group in Active Directory Domain Services can access those keys in order to decrypt the data that is encrypted by DKM.

## ADFS Service Startup Process

* ADFS Service starts
* It reads service settings from the database (Windows Internal Database (WID)) in XML format
* As part of the process, it loads the ADFS certificate collection (Reads certificate encrypted PFX blob (base64 encoded) from the XML object)
* Decodes Base64 string
* ADFS DKM Master Key is not used to decrypt certificate. DKM Key is derived (standard NIST SP 800-108)
* Derived key is used and certificate is decrypted

## ADFS DKM Master Key

* The ADFS DKM master key(s) are stored in Active Directory (AD).
* An examplle of an ADFS DKM Container in AD would be `CN=ADFS,CN=Microsoft,CN=Program Data,DC=azsentinel,DC=local`
* Inside of the AD container there are groups and inside of one of them there is an AD contact object that contains the DKM key used to decrypt AD FS certificates.
* The DKM key is stored in the `thumbnailPhoto` attribute of the AD contact object.
* One could read the DKM key as a byte array and convert it to a usable string from AD by running the following command:

```PowerShell
$key=(Get-ADObject -filter 'ObjectClass -eq "Contact" -and name -ne "CryptoPolicy"' -SearchBase "CN=ADFS,CN=Microsoft,CN=Program Data,DC=azsentinel,DC=local" -Properties thumbnailPhoto).thumbnailPhoto

[System.BitConverter]::ToString($key)
```

A threat actor would need to obtain the ADFS DKM Master Key to then use it in the process to decrypt AD FS certificates. If the AD FS token signing certificate is decrypted from the AD FS configuration settings and exported, it can then be used sign new SAML tokens and impersonate users in a federated environment.

## Audit Rule on ADFS DKM Container

* We can create an audit rule on the DKM container or directly on the AD contact object that contains the DKM key.
* We need to add an Access Control Entry (ACE) to the System Access Control List (SACL) of the AD object and audit access requests to it.

**Audit Rule on DKM Container**

```PowerShell
Set-AuditRule -AdObjectPath 'AD:\CN=ADFS,CN=Microsoft,CN=Program Data,DC=azsentinel,DC=local' -WellKnownSidType WorldSid -Rights GenericRead -InheritanceFlags None -AuditFlags Success
```

**Audit Rule on Specific AD Contact Object**

```PowerShell
Set-AuditRule -AdObjectPath 'AD:\CN=<Contact Object>,CN=<DKM Container>,CN=ADFS,CN=Microsoft,CN=Program Data,DC=azsentinel,DC=local' -WellKnownSidType WorldSid -Rights GenericRead -InheritanceFlags None -AuditFlags Success
```

**Results**:
* Event 4662 does not translate the thumbnailPhoto GUID to the "thumbnailPhoto" string by default. That needs to be an enrichment.
    * thumbnailPhoto Attribute GUID: `8d3bca50-1d7e-11d0-a081-00aa006c33ed`
    * The attribute is not part of the object name in the security event. It is an attribute/property. Therefore, the value would show up in the field name Properties
* We can filter events also by using the ObjectType GUID of the AD contact object and then look for the thumbnailPhoto GUID value.

**Example**

```xml
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"> 
- <System> 
<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" /> 
<EventID>4662</EventID> 
<Version>0</Version> 
<Level>0</Level> 
<Task>14080</Task> 
<Opcode>0</Opcode> 
<Keywords>0x8020000000000000</Keywords> 
<TimeCreated SystemTime="2020-12-20T07:53:41.092054600Z" /> 
<EventRecordID>330446</EventRecordID> 
<Correlation /> 
<Execution ProcessID="708" ThreadID="836" /> 
<Channel>Security</Channel> 
<Computer>DC01.azsentinel.local</Computer> 
<Security /> 
</System> 
- <EventData> 
<Data Name="SubjectUserSid">S-1-5-21-1640822366-3528877384-3060188657-1103</Data> 
<Data Name="SubjectUserName">adfsuser</Data> 
<Data Name="SubjectDomainName">AZSENTINEL</Data> 
<Data Name="SubjectLogonId">0x4235ba</Data> 
<Data Name="ObjectServer">DS</Data> 
<Data Name="ObjectType">%{5cb41ed0-0e4c-11d0-a286-00aa003049e2}</Data> 
<Data Name="ObjectName">%{8cd0a7fa-b3c9-4572-85e5-9359c2783031}</Data> 
<Data Name="OperationType">Object Access</Data> 
<Data Name="HandleId">0x0</Data> 
<Data Name="AccessList">%%7684</Data> 
<Data Name="AccessMask">0x10</Data> 
<Data Name="Properties">%%7684 {77b5b886-944a-11d1-aebd-0000f80367c1} {8d3bca50-1d7e-11d0-a081-00aa006c33ed} {5cb41ed0-0e4c-11d0-a286-00aa003049e2}</Data> 
<Data Name="AdditionalInfo">-</Data> 
<Data Name="AdditionalInfo2" /> 
</EventData> 
</Event>
```

## References

* https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-overview
* https://docs.microsoft.com/en-us/microsoft-365/compliance/exchange-online-secures-email-secrets?view=o365-worldwide
* https://www.youtube.com/watch?v=5dj4vOqqGZw
* https://github.com/fireeye/ADFSDump/tree/master/ADFSDump
* https://www.powershellgallery.com/packages/AADInternals/0.2.5/Content/ADFS_utils.ps1
* https://www.powershellgallery.com/packages/AADInternals/0.2.3/Content/Export-ADFSSigninCertificate.ps1
* https://msresource.wordpress.com/2016/05/04/the-use-of-distributed-key-manager-dkm-in-active-directory-federation-services-ad-fs/