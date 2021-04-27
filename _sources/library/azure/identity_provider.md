# Identity Provider

We are not longer going to change a name and password to a server. Instead, the client is going to get what is called a security token from the Identity Provider. The client then presents the security token to the server. The server then validates the token and trusts it because it has a trus relationships with the identity provider. The identity provider signing key is enough to check the cryptographic signature of the token.

## What is a token?

A token is a signed document. A cryptographic signed document. A token contains claims. Claims are information about the identity calling the server. 