# AppCompat Shim Databases
## Description
Application Compatibility fixes resolve compatibility issues between an application and how it interacts
with Windows. The Fix it solution center, a Microsoft website dedicated to Fix Its, allows users to select
their problem area e.g. Windows, Internet Explorer, Office, etc. ad then select the problem type which
can be anything from performance to security related problems. The website then provides a list of
possible solutions. These solutions are released in the form of a Shim Database (SDB). According to Microsoft, an application compatibility shim is a small library that transparently intercepts an API (via hooking), changes the parameters passed, handles the operation itself, or redirects the operation elsewhere, such as additional code stored on a system. Today, shims are mainly used for compatibility purposes for legacy applications. While shims serve a legitimate purpose, they can also be used in a malicious manner.


## Hypothesis
Adversaries might be abusing features of the Application Compatability infrastructure and installing/registering shim databases to maintain persistence in my environment.


## Events

| Source | EventID | Field | Details | Reference | 
|--------|---------|-------|---------|-----------| 
| Sysmon | 1,12,13,11 | Image | sdbinst.exe | [Matthew McWhirt, Jon Erickson, DJ Palombo](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html) |
| Sysmon | 12 | TargetObject | "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom" | [Matthew McWhirt, Jon Erickson, DJ Palombo](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html) |
| Sysmon | 12 | TargetObject | "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" | [Matthew McWhirt, Jon Erickson, DJ Palombo](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html) |
| Sysmon | 12 | EventType | CreateKey | [Matthew McWhirt, Jon Erickson, DJ Palombo](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html) |
| Sysmon | 13 | TargetObject | "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" AND ("DatabaseDescription" OR "DatabaseType" OR "DatabaseDescription" OR "DatabasePath") | [Matthew McWhirt, Jon Erickson, DJ Palombo](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html) |
| Sysmon | 11 | TargetFilename | “C:\Windows\AppPatch\Custom” OR “C:\Windows\AppPatch\Custom64” | [Matthew McWhirt, Jon Erickson, DJ Palombo](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html) |


## Hunter Notes
* Monitor for new shim database files created in the default shim database directories of “C:\Windows\AppPatch\Custom” and “C:\Windows\AppPatch\Custom\Custom64”
  * Creating Shim databases might not be an anomaly in your environment (maybe?)
  * C:\Windows\AppPatch\Custom directory is used to store SDB files for 32bit applications. If you install a patch for a 64bit Application the SDB file would be located in the
C:\Windows\AppPatch\Custom\Custom64 directory.
  * It is not a requirement that the SDB files are located in these directories, it is just a convention Microsoft uses. The SDB files can be in any accessible directory location and can use any filename.
* It is even possible to have SDB files with different file extensions. The only caveat to the directory locations is for 64bit applications. If it is a 64bit application the SDB file must have Custom64 somewhere in its directory path.
  * Maybe you can do a search for EID 13 AND TargetObject:("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" AND "DatabasePath") NOT Details:*.sdb when looking for databases with a different extension.
  * If you are monitoring for .sdb files being created in your environment then just use a wildcard *.sdb for the Details field of EID 13.
* Directly adding the Registry values circumvent sdbinst.exe and extra control panel entries.


## Hunting Techniques Recommended

- [x] Grouping
- [x] Searching
- [ ] Clustering
- [x] Stack Counting
- [ ] Scatter Plots
- [ ] Box Plots
- [ ] Isolation Forests
