# Logon Session

According to Microsoft documentation, A logon session is a computing session that begins when a user authentication is successful and ends when the user logs off of the system.

When a user is successfully authenticated, the authentication package creates a logon session and returns information to the Local Security Authority (LSA) that is used to create a token for the new user. This token includes, among other things, a locally unique identifier (LUID) for the logon session, called the logon Id.

From a security event perspective the logon_id is first seen when a successful authentication event occurs.
Based on the documentation provided by Microsoft and OSSEM, events from the Audit Logon subcategory are related to the creation of logon sessions and occur on the computer that was accessed. For an interactive logon, events are generated on the computer that was logged on to. For a network logon, such as accessing a share, events are generated on the computer that hosts the resource that was accessed.

## References

* https://docs.microsoft.com/en-us/windows/desktop/secauthn/lsa-logon-sessions
