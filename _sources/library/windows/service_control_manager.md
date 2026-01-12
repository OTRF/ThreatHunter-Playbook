# Service Control Manager

The service control manager (SCM) is started at system boot. It is a remote procedure call (RPC) server, so that service configuration and service control programs can manipulate services on remote machines.

The service functions provide an interface for the following tasks performed by the SCM:

* Maintaining the database of installed services.
* Starting services and driver services either upon system startup or upon demand.
* Enumerating installed services and driver services.
* Maintaining status information for running services and driver services.
* Transmitting control requests to running services.
* Locking and unlocking the service database.

## Database of Installed Services

The SCM maintains a database of installed services in the registry. The database is used by the SCM and programs that add, modify, or configure services. The following is the registry key for this database: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`. This key contains a subkey for each installed service and driver service. The name of the subkey is the name of the service.

This database is also known as the `ServicesActive database` or the SCM database. You must use the functions provided by the SCM, instead of modifying the database directly.

## Services and RPC/TCP

Starting with Windows Vista, the service control manager (SCM) supports remote procedure calls over both Transmission Control Protocol (RPC/TCP) and named pipes (RPC/NP). Client-side SCM functions use RPC/TCP by default. RPC/TCP is appropriate for most applications that use SCM functions remotely, such as remote administration or monitoring tools. The server interface is identified by UUID 367ABB81-9844-35F1-AD32-98F038001003, version 2.0, using the RPC well-known endpoint "\PIPE\svcctl". The server MUST use RPC over SMB, ncacn_np or RPC over TCP, or ncacn_ip_tcp as the RPC protocol sequence to the RPC implementation.

When a service calls a remote SCM function, the client-side SCM first attempts to use RPC/TCP to communicate with the server-side SCM. If the server is running a version of Windows that supports RPC/TCP and allows RPC/TCP traffic, the RPC/TCPP connection will succeed. If the server is running a version of Windows that does not support RPC/TCP, or supports RPC/TCP but is operating behind a firewall which allows only named pipe traffic, the RPC/TCP connection times out and the SCM retries the connection with RPC/NP.

## SCM Handles

The SCM supports handle types to allow access to the following objects.

* The database of installed services.
* A service.
* The database lock.

An SCManager object represents the database of installed services. It is a container object that holds service objects. The OpenSCManager function returns a handle to an SCManager object on a specified computer. This handle is used when installing, deleting, opening, and enumerating services and when locking the services database.

A service object represents an installed service. The CreateService and OpenService functions return handles to installed services.

The OpenSCManager, CreateService, and OpenService functions can request different types of access to SCManager and service objects. The requested access is granted or denied depending on the access token of the calling process and the security descriptor associated with the SCManager or service object.

## OpenSCManagerA function

Establishes a connection to the service control manager on the specified computer and opens the specified service control manager database.

```
SC_HANDLE OpenSCManagerA(
  LPCWSTR lpMachineName,
  LPCWSTR lpDatabaseName,
  DWORD   dwDesiredAccess
);
```

`lpMachineName`

The name of the target computer. If the pointer is NULL or points to an empty string, the function connects to the service control manager on the local computer.

`lpDatabaseName`

The name of the service control manager database. This parameter should be set to SERVICES_ACTIVE_DATABASE. If it is NULL, the SERVICES_ACTIVE_DATABASE database is opened by default.

`dwDesiredAccess`

The access to the service control manager. For a list of access rights, see Service Security and Access Rights.

Before granting the requested access rights, the system checks the access token of the calling process against the discretionary access-control list of the security descriptor associated with the service control manager.

The SC_MANAGER_CONNECT access right is implicitly specified by calling this function.

Before granting the requested access rights, the system checks the access token of the calling process against the discretionary access-control list of the security descriptor associated with the service control manager.

## References

* https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager
* https://docs.microsoft.com/en-us/windows/win32/services/scm-handles
* https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagera
* https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw
* https://docs.microsoft.com/en-us/windows/win32/services/database-of-installed-services
* https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
* https://docs.microsoft.com/en-us/windows/win32/services/services-and-rpc-tcp
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/4c8b7701-b043-400c-9350-dc29cfaa5e7a
