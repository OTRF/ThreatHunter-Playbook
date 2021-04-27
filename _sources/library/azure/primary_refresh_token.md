# Primary Refresh Token

Primary Refresh Token which is a long-term token that is stored on the device, where possible using a Trusted Platform Module (TPM) for extra security.

A Primary Refresh Token can be compared to a long-term persistent Ticket Granting Ticket (TGT) in Active Directory. It is a token that enables users to sign in once on their Azure AD connected device and then automatically sign in to Azure AD connected resources. 

In OAuth2 terminology, a refresh token is a long lived token that can be used to request new access tokens, which are then sent to the service you want to authenticate to. A regular refresh token is issued when a user is signed in to an application, website or mobile app (which are all applications in Azure AD terminology). This refresh token is only valid for the user that requested it, only has access to what that application is granted access to and can only be used to request access tokens for that same application. The Primary Refresh Token however can be used to authenticate to any application, and is thus even more valuable.



## What is TPM?

Trusted Platform Module (TPM). Trusted Platform Module (TPM) technology is designed to provide hardware-based, security-related functions. A TPM chip is a secure crypto-processor that helps you with actions such as generating, storing, and limiting the use of cryptographic keys.

## What are JWTs?


## References

* https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/