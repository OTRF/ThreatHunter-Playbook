# SysKey

Syskey is a utility that strongly encrypts the hashed password information in the SAM database in order to protect it against offline password cracking attacks. The key used by Syskey to encrypt the password hashes (called bootkey or system key) can be generated and stored in three ways. The method to use is selected when running syskey.exe on the host.

* Using a user supplied passphrase(actually the MD5 hash of it). The system will prompt for the passphrase during startup.
* Using a system generated key stored on a floppy. The system will ask for the boot floppy during startup.
* Using a system generated key stored on the "the local system using a complex  obfuscation algorithm" (Microsoft). This is the default method used.

The Syskey is taken from four separte keys:

* HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\JD
* HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Skew1
* HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Data
* HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\GBG

However, the actual data needed is stored in a hidden field of the key that cannot be seen using tools like regedit. Specifically, each part of the key is stored in the key's Class attribute, and is stored as a Unicode string giving the hex value of that piece of the key.

The same keys are also accessed during the Windows boot phase by the main thread of Smss (Session Manager) which starts the Winlogon process, the Winlogon process required to load the Local Security Subsystem (Lsass) which in turn loads the Security Accounts Manager
(SAM) service (the interface to the SAM database), and the bootkey generation phase by Syskey.exe tool.

## References

* https://docs.microsoft.com/en-us/security-updates/securitybulletins/1999/ms99-056
* https://download.openwall.net/pub/projects/john/contrib/pwdump/syskey.txt
* http://moyix.blogspot.com/2008/02/syskey-and-sam.html
