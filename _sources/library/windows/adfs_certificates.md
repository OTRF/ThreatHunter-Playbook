# Active Directory Federation Services (ADFS) Certificates

There are 4 tyoes of ADFS certificates
* Token Signing
    * Used to digitally sign security tokens issued by ADFS
    * Automatically generated and can be self-signed 
* Token Decrypting
    * Used to decrypt tokens received
    * It can be self-signed
* Service Communications
    * Server authentication certificate used for windows communication foundation (WCF) Message security
    * Trusted and signed by a third party trusted CA
* Security Sockets Layer (SSL)
    * Used to secure web traffic
    * Issued and signed by trusted third party CA

Note: The SSL and Service Communications certificates can be the same (they both serve different purposes but it is ok to use the same)

## Updating Certificates

Disable `AutoCertificateRollOver` to be able to update certificates

```PowerShell
Set-AdfsProperties -AutoCertificateRollover $false
```

