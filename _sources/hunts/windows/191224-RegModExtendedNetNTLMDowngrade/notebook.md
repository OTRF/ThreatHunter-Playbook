---
jupytext:
  formats: md:myst
  text_representation:
    extension: .md
    format_name: myst
    format_version: '1.3'
    jupytext_version: 1.14.1
kernelspec:
  display_name: Python 3
  language: python
  name: python3
---

# Registry Modification for Extended NetNTLM Downgrade

## Hypothesis

Adversaries might be downgrading the challenge/response authentication protocol used for network logons, the minimum security negotiated for applications using NTLMSSP, and security settings that restrict outgoing NTLM traffic to remote servers in my environment

## Technical Context

LAN Manager (LM) includes client computer and server software from Microsoft that allows users to link personal devices together on a single network.
Network capabilities include transparent file and print sharing, user security features, and network administration tools.
In Active Directory domains, the Kerberos protocol is the default authentication protocol.
However, if the Kerberos protocol is not negotiated for some reason, Active Directory uses LM, NTLM, or NTLM version 2 (NTLMv2).

LAN Manager authentication includes the LM, NTLM, and NTLMv2 variants, and it is the protocol that is used to authenticate all client devices running the Windows operating system when they perform the following operations

* Join a domain
* Authenticate between Active Directory forests
* Authenticate to domains based on earlier versions of the Windows operating system
* Authenticate to computers that do not run Windows operating systems, beginning with Windows 2000
* Authenticate to computers that are not in the domain

Prior to Windows NT 4.0 Service Pack 4 (SP4), Windows NT supported two kinds of challenge/response authentication -> LanManager (LM) challenge/response and Windows NT challenge/response (also known as NTLM challenge/response)
Windows NT also supported session security mechanisms that provided for Message confidentiality and integrity.
To allow access to servers that only support LM authentication, Windows NT clients prior to SP4 always use both, even to Windows NT servers that supported NTLM authentication.

LM authentication is not as strong as Windows NT authentication so some customers may want to disable its use, because an attacker eavesdropping on network traffic will attack the weaker protocol.
A successful attack can compromise the user's password.
Microsoft has developed an enhancement to NTLM called NTLMv2 that significantly improves both the authentication and session security mechanisms.

In addition, the implementation of the NTLM Security Service Provider (SSP) has been enhanced to allow clients to control which variants of NTLM are used, and to allow servers to control which variants they will accept, by setting a new registry key appropriately.
It also allows clients and servers to require the negotiation of Message confidentiality (encryption), Message integrity, 128-bit encryption, and NTLMv2 session security.

Control of NTLM security is through the following registry key

* HKEY_LOCAL_MACHINE\System\CurrentControlSet\control\LSA

Choice of the authentication protocol variants used and accepted is through the following value of that key

Value -> LMCompatibilityLevel
Value Type -> REG_DWORD - Number
Valid Range -> 0-5
Default -> 0
Description -> This parameter specifies the type of authentication to be
used.

Level 0 - Send LM response and NTLM response; never use NTLMv2 session security
Level 1 - Use NTLMv2 session security if negotiated
Level 2 - Send NTLM authenication only
Level 3 - Send NTLMv2 authentication  only
Level 4 - DC refuses LM authentication
Level 5 - DC refuses LM and NTLM authenication (accepts only NTLMv2)

Control over the minimum security negotiated for applications using NTLMSSP is
through the following key

* HKEY_LOCAL_MACHINE\System\CurrentControlSet\control\LSA\MSV1_0

The following values are for this key

  * Value -> NtlmMinClientSec
  * Value Type -> REG_DWORD - Number
  * Valid Range -> the logical 'or' of any of the following values
    * 0x00000010
    * 0x00000020
    * 0x00080000
    * 0x20000000
  * Default -> 0

  * Value -> NtlmMinServerSec
  * Value Type -> REG_DWORD - Number
  * Valid Range -> same as NtlmMinClientSec
  * Default -> 0
  * Description -> This parameter specifies the minimum security to be used.
    * 0x00000010  Message integrity
    * 0x00000020  Message confidentiality
    * 0x00080000  NTLMv2 session security
    * 0x20000000  128 bit encryption

## Offensive Tradecraft

An adversary with administrator rights to a compromised endpoint could easily modify these settings and downgrade the challenge/response authentication protocol used for network logons and the minimum security negotiated for applications using NTLMSSP.
This is very dangerous because it could enable NetNTLMv1 as a client on the compromised endpoit and make it authenticate to a rogue SMB server to capture the clientâ€™s response (an NTLM Hash).
If an organization is already restricting outgoing NTLM traffic to remote servers, it can be easily disabled by modifying the following registry key Property and setting it to 0.
  * Key -> HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
  * Property -> RestrictSendingNTLMTraffic

## Pre-Recorded Security Datasets

| Metadata  |    Value  |
|:----------|:----------|
| docs      | https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-191225045202.html        |
| link      | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/empire_monologue_netntlm_downgrade.zip  |

### Download Dataset

```{code-cell} ipython3
import requests
from zipfile import ZipFile
from io import BytesIO

url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/empire_monologue_netntlm_downgrade.zip'
zipFileRequest = requests.get(url)
zipFile = ZipFile(BytesIO(zipFileRequest.content))
datasetJSONPath = zipFile.extract(zipFile.namelist()[0])
```

### Read Dataset

```{code-cell} Ipython3
import pandas as pd
from pandas.io import json

df = json.read_json(path_or_buf=datasetJSONPath, lines=True)
```

## Analytics

A few initial ideas to explore your data and validate your detection logic:

### Analytic I

Look for non-system accounts getting a handle and accessing `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa` and `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa\MSV1_0` registry keys from a non-lsass process.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows Registry | Microsoft-Windows-Security-Auditing | Process accessed Windows registry key | 4663 |
| Windows Registry | Microsoft-Windows-Security-Auditing | User accessed Windows registry key | 4663 |
| Windows Registry | Microsoft-Windows-Security-Auditing | Process requested access Windows registry key | 4656 |
| Windows Registry | Microsoft-Windows-Security-Auditing | User requested access Windows registry key | 4656 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, SubjectUserName, ProcessName, ObjectName, AccessMask, EventID, SubjectLogonId
FROM dataTable
WHERE LOWER(Channel) = "security"
    AND EventID IN (4663, 4656)
    AND ObjectType = 'Key'
    AND (ObjectName LIKE "%Lsa" OR ObjectName LIKE "%Lsa\MSV1_0")
    AND ProcessName NOT LIKE "%lsass.exe"
    AND SubjectLogonId != "0x3e7"
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','SubjectUserName','ProcessName','ObjectName','AccessMask','EventID','SubjectLogonId']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'].isin([4663,4656]))
    & (df['ObjectType'] == 'Key')
    & (
      (df['ObjectName'].str.lower().str.endswith('lsa', na=False))
      | (df['ObjectName'].str.lower().str.endswith('lsa\msv1_0', na=False))
    )
    & (~df['ProcessName'].str.lower().str.endswith('lsass.exe', na=False))
    & (df['SubjectLogonId'] != '0x3e7')
]
)
```

### Analytic II

Look for processes modifying the values of the following registry key properties LMCompatibilityLevel,NtlmMinClientSec and RestrictSendingNTLMTraffic.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows Registry | Microsoft-Windows-Security-Auditing | Process modified Windows registry key value | 4657 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, SubjectUserName, ProcessName, ObjectName, OldValue, NewValue, SubjectLogonId
FROM dataTable
WHERE LOWER(Channel) = "security"
    AND EventID = 4657
    AND ObjectValueName in ("LMCompatibilityLevel","NtlmMinClientSec","RestrictSendingNTLMTraffic")
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','SubjectUserName','ProcessName','ObjectName','OldValue','NewValue','SubjectLogonId']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4657)
    & (df['ObjectValueName'].isin(['LMCompatibilityLevel','NtlmMinClientSec','RestrictSendingNTLMTraffic']))
]
.head()
)
```

### Analytic III

Look for processes modifying the values of the following registry key properties LMCompatibilityLevel,NtlmMinClientSec and RestrictSendingNTLMTraffic.

| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|
| Windows Registry | Microsoft-Windows-Sysmon/Operational | Process modified Windows registry key value | 13 |

#### Logic

```{code-block}
SELECT `@timestamp`, Hostname, Image, TargetObject, Details
FROM dataTable
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 13
    AND (
        TargetObject LIKE "%LMCompatibilityLevel" OR
        TargetObject LIKE "%NtlmMinClientSec" OR
        TargetObject LIKE "%RestrictSendingNTLMTraffic"
    )
```

#### Pandas Query

```{code-cell} Ipython3
(
df[['@timestamp','Hostname','Image','TargetObject','Details']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 13)
    & (
      (df['TargetObject'].str.endswith('LMCompatibilityLevel', na=False))
      | (df['TargetObject'].str.endswith('NtlmMinClientSec', na=False))
      | (df['TargetObject'].str.endswith('RestrictSendingNTLMTraffic', na=False))
    )
]
.head()
)
```

## Known Bypasses

## False Positives

## Hunter Notes

* Make sure you have audit rules (SACL) applied to \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa and \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa\MSV1_0
* You can take the ProcessId of the process that performed the downgrade and explore its parents.

## Hunt Output

| Type | Link |
| :----| :----|
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_net_ntlm_downgrade.yml |
| Sigma Rule | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry_event/registry_event_net_ntlm_downgrade.yml |

## References
* https://shenaniganslabs.io/2019/01/14/Internal-Monologue.html
* https://jeffpar.github.io/kbarchive/kb/147/Q147706/
* https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
* https://twitter.com/elad_shamir/status/975670116519063553
* https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers
* https://github.com/OTRF/Set-AuditRule/blob/master/registry/lsa.md
* https://www.andreafortuna.org/2018/03/26/retrieving-ntlm-hashes-without-touching-lsass-the-internal-monologue-attack/
* https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks
