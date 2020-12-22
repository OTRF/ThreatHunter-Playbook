# Mimikatz OpenProcess Modules

## Author

[dim0x69 - blog.3or.de](https://blog.3or.de/hunting-mimikatz-with-sysmon-monitoring-openprocess.html)

## Details

| module | OpenProcess caller function | destination process / destination service | ACCESS\_MASK | ACCESS\_MASK translated | comment |
|---------|---------|---------|---------|---------|---------|
| sekurlsa::* | kuhl\_m\_sekurlsa\_acquireLSA() | lsass.exe | PROCESS\_VM\_READ \| PROCESS\_QUERY\_INFORMATION | 0x1410 | for Windows Version < 5 |
| sekurlsa::* | kuhl\_m\_sekurlsa\_acquireLSA() | lsass.exe | PROCESS\_VM\_READ \| PROCESS\_QUERY\_LIMITED\_INFORMATION | 0x1010 | for Windows Version >= 6 |
| lsadump::lsa /patch | kuhl\_m\_lsadump\_lsa\_getHandle() | SamSs | PROCESS\_VM\_READ \| PROCESS\_VM_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 |
| lsadump::lsa /inject | kuhl\_m\_lsadump\_lsa\_getHandle() | SamSs | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE  \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION \| PROCESS\_CREATE\_THREAD | 0x143a |
| lsadump::trust /patch | kuhl_m_lsadump_lsa_getHandle() | SamSs | PROCESS_VM_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION| 0x1438 |
| minesweeper::infos | kuhl\_m\_minesweeper\_infos() | minesweeper.exe | PROCESS\_VM\_READ \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1418 |
| misc:detours | kuhl\_m\_misc\_detours\_callback\_process() | * |GENERIC\_READ | |omitted because of the very generic ACCESS_MASK |
| misc:memssp |  kuhl\_m\_misc\_memssp() | lsass.exe | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 |
| process::suspend, process:stop, process:resume,process:imports, process:exports |kuhl\_m\_process\_genericOperation()|||| omitted because of the very generic ACCESS_MASKs|
| vault::cred /patch|  kuhl\_m\_vault\_cred() | SamSs | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 | |
| token::list, token::elevate, token::run | querying all processes on the system |*||first 0x1400 then 0x40| all three commands result in a call to kull\_m\_token\_getTokens() which first iterates over **all** processes and threads with OpenProcess(PROCESS\_QUERY\_INFORMATION (0x1400)) (kull\_m\_token\_getTokens\_process\_callback()) and then again to get the tokens OpenProcess(PROCESS\_DUP\_HANDLE (0x40)) (in kull\_m\_handle\_getHandlesOfType_callback()) to duplicate the Tokens. This results in many thousand (!) Events with ID 10 (!)|
| crypto::cng | kull\_m\_patch\_genericProcessOrServiceFromBuild() via  kuhl\_m\_crypto\_p\_cng() |KeyIso | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 | |
| event::drop | kull\_m\_patch\_genericProcessOrServiceFromBuild() via  kuhl\_m\_event\_drop() | EventLog | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 | ** this event does not get logged! :O mimikatz seems to be fast enough to apply the patch before the event gets logged!**|
| misc::ncroutemon | kull\_m\_patch\_genericProcessOrServiceFromBuild() via  kuhl\_m\_misc\_ncroutemon() | dsNcService| PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 | |
| ts::multirdp| kull\_m\_patch\_genericProcessOrServiceFromBuild() via  kuhl\_m\_ts\_multirdp() | TermService | PROCESS\_VM\_READ \| PROCESS\_VM\_WRITE \| PROCESS\_VM\_OPERATION \| PROCESS\_QUERY\_INFORMATION | 0x1438 |

## References

* https://blog.3or.de/hunting-mimikatz-with-sysmon-monitoring-openprocess.html
