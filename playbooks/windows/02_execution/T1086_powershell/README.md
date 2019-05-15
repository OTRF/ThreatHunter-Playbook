# Powershell

## Technique ID(s): T1086

## Description

> PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer. PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk. Administrator permissions are required to use PowerShell to connect to remote systems.

[MITRE ATT&CK - T1086](https://attack.mitre.org/wiki/Technique/T1086)

## Techniques Detection

| Variant | Description |
|--------|---------|
| Basic PowerShell Execution | Detection of PowerShell execution locally or remotely. This only focues on execution of PowerShell and not on what happens after the execution or the specific goal. This can be linked to several PowerShell execution variants |
| Alternate Signed PowerShell Hosts | Detection of the abuse of signed PowerShell Hosts bypassing application whitelisting and potentially constrained language mode. This focuses on PowerShell hosts beyond powershell.exe,powershell_ise.exe or wsmprovhost.exe |