# Process Security and Access Rights

## Author

[Microsoft](https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx)

## Details

The Microsoft Windows security model enables you to control access to process objects. When a user logs in, the system collects a set of data that uniquely identifies the user during the authentication process, and stores it in an access token. This access token describes the security context of all processes associated with the user. The security context of a process is the set of credentials given to the process or the user account that created the process.You can use a token to specify the current security context for a process using the CreateProcessWithTokenW function. You can specify a security descriptor for a process when you call the CreateProcess, CreateProcessAsUser, or CreateProcessWithLogonW function. If you specify NULL, the process gets a default security descriptor. The ACLs in the default security descriptor for a process come from the primary or impersonation token of the creator.To retrieve a process's security descriptor, call the GetSecurityInfo function. To change a process's security descriptor, call the SetSecurityInfo function.The valid access rights for process objects include the standard access rights and some process-specific access rights.

| Value | Meaning |
|---------|---------|
| Value | Meaning |
| PROCESS_ALL_ACCESS (0x1fffff) | All possible access rights for a process object. |
| PROCESS_CREATE_PROCESS (0x0080) | Required to create a process. |
| PROCESS_CREATE_THREAD (0x0002) | Required to create a thread. |
| PROCESS_DUP_HANDLE (0x0040) | Required to duplicate a handle using DuplicateHandle. |
| PROCESS_QUERY_INFORMATION (0x0400) | Required to retrieve certain information about a process, such as its token, exit code, and priority class (see OpenProcessToken). |
| PROCESS_QUERY_LIMITED_INFORMATION (0x1000) | Required to retrieve certain information about a process. A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION. |
| PROCESS_SET_INFORMATION (0x0200) | Required to set certain information about a process, such as its priority class (see SetPriorityClass). |
| PROCESS_SET_QUOTA (0x0100) | Required to set memory limits using SetProcessWorkingSetSize. | 
| PROCESS_SUSPEND_RESUME (0x0800) | Required to suspend or resume a process. |
| PROCESS_TERMINATE (0x0001) | Required to terminate a process using TerminateProcess. |
| PROCESS_VM_OPERATION (0x0008) | Required to perform an operation on the address space of a process |
| PROCESS_VM_READ (0x0010) | Required to read memory in a process using ReadProcessMemory. |
| PROCESS_VM_WRITE (0x0020) | Required to write to memory in a process using WriteProcessMemory. |
| SYNCHRONIZE (0x00100000L) | Required to wait for the process to terminate using the wait functions. |

## References

* https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx
