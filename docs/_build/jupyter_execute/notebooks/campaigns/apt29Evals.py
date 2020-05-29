# Free Telemetry Notebook


|               |    |
|:--------------|:---|
| Group         | APT29 |
| Description   | APT29 is a threat group that has been attributed to the Russian government and has operated since at least 2008. This group reportedly compromised the Democratic National Committee starting in the summer of 2015 |
| Author        | [Open Threat Research - APT29 Detection Hackathon](https://github.com/OTRF/detection-hackathon-apt29) |
    

### Import Libraries

from pyspark.sql import SparkSession

### Start Spark Session

spark = SparkSession.builder.getOrCreate()
spark.conf.set("spark.sql.caseSensitive", "true")

### Decompress Dataset

!wget https://github.com/hunters-forge/mordor/raw/master/datasets/large/apt29/day1/apt29_evals_day1_manual.zip

!unzip apt29_evals_day1_manual.zip

### Import Datasets

df_day1_host = spark.read.json('apt29_evals_day1_manual_2020-05-01225525.json')

### Create Temporary SQL View

df_day1_host.createTempView('apt29Host')

## Adversary - Detection Steps

## 1.A.1. User Execution
**Procedure:** User Pam executed payload rcs.3aka3.doc

**Criteria:** The rcs.3aka3.doc process spawning from explorer.exe


### Detection Type:Telemetry(None)

**Query ID:204B00B6-A92B-4EF7-8510-4FB237703147**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND LOWER(ParentImage) LIKE "%explorer.exe"
    AND LOWER(Image) LIKE "%3aka3%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:52540C1E-DD76-41B2-93ED-CFBA2B94ECF7**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE LOWER(Channel) = "security"
    AND EventID = 4688
    AND LOWER(ParentProcessName) LIKE "%explorer.exe"
    AND LOWER(NewProcessName) LIKE "%3aka3%"

'''
)
df.show(100,truncate = False, vertical = True)

### Detection Type:General(None)

**Query ID:DFD6A782-9BDB-4550-AB6B-525E825B095E**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
  AND EventID = 13
  AND TargetObject RLIKE '.*\\\\\\\\AppCompatFlags\\\\\\\\Compatibility Assistant\\\\\\\\Store\\\\\\\\.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 1.A.2. Masquerading
**Procedure:** Used unicode right-to-left override (RTLO) character to obfuscate file name rcs.3aka3.doc (originally cod.3aka.scr)

**Criteria:** Evidence of the right-to-left override character (U+202E) in the rcs.3aka.doc process ​OR the original filename (cod.3aka.scr)


### Detection Type:Telemetry(None)

**Query ID:F4C71BF4-E068-493D-ABAA-0C5DFA02875D**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND LOWER(Image) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:D94222A0-72F9-4F1E-84A9-F14CA1098D44**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE LOWER(Channel) = "security"
    AND EventID = 4688
    AND LOWER(NewProcessName) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 1.A.3. Uncommonly Used Port
**Procedure:** Established C2 channel (192.168.0.5) via rcs.3aka3.doc payload over TCP port 1234

**Criteria:** Established network channel over port 1234


### Detection Type:Telemetry(None)

**Query ID:B53A710B-43AB-4B57-BD92-4E787D494978**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 3
    AND LOWER(Image) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:1BAC5645-83CD-4D6F-A4F8-659084401F47**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE LOWER(Channel) = "security"
  AND EventID = 5156
  AND LOWER(Application) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 1.A.4. Standard Cryptographic Protocol
**Procedure:** Used RC4 stream cipher to encrypt C2 (192.168.0.5) traffic

**Criteria:** Evidence that the network data sent over the C2 channel is encrypted


### Detection Type:None(None)

**Query ID:E12B701E-1222-413C-BCAF-F357CB769B3E**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
  AND EventID = 7
  AND Image LIKE "%3aka3%"
  AND LOWER(ImageLoaded) LIKE '%bcrypt.dll'

'''
)
df.show(100,truncate = False, vertical = True)

## 1.B.1. Command-Line Interface
**Procedure:** Spawned interactive cmd.exe

**Criteria:** cmd.exe spawning from the rcs.3aka3.doc​ process


### Detection Type:Telemetry(Correlated)

**Query ID:4799C203-573A-49CB-ACE4-8C4C5CD3862A**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
  AND EventID = 1
  AND LOWER(ParentImage) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'
  AND LOWER(Image) LIKE "%cmd.exe"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:C8D664CD-48EE-4663-AE49-D5B0B19014C7**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE LOWER(Channel) = "security"
  AND EventID = 4688
  AND LOWER(ParentProcessName) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'
  AND LOWER(NewProcessName) LIKE "%cmd.exe"

'''
)
df.show(100,truncate = False, vertical = True)

## 1.B.2. PowerShell
**Procedure:** Spawned interactive powershell.exe

**Criteria:** powershell.exe spawning from cmd.exe


### Detection Type:Telemetry(Correlated)

**Query ID:C1DBF5F2-21D5-45E4-8D9A-44905F1F8242**

df = spark.sql(
'''
SELECT Message
FROM apt29Host a
INNER JOIN (
    SELECT ProcessGuid
    FROM apt29Host
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 1
        AND LOWER(ParentImage) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'
        AND LOWER(Image) LIKE '%cmd.exe'
) b
ON a.ParentProcessGuid = b.ProcessGuid
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND LOWER(Image) LIKE '%powershell.exe'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:43B46661-3407-4302-BA8C-EE772C677DCB**

df = spark.sql(
'''
SELECT Message
FROM apt29Host a
INNER JOIN (
    SELECT NewProcessId
    FROM apt29Host
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
        AND LOWER(ParentProcessName) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'
        AND LOWER(NewProcessName) LIKE '%cmd.exe'
) b
ON a.ProcessId = b.NewProcessId
WHERE LOWER(Channel) = "security"
    AND EventID = 4688
    AND LOWER(NewProcessName) LIKE '%powershell.exe'

'''
)
df.show(100,truncate = False, vertical = True)

## 2.A.1. File and Directory Discovery
**Procedure:** Searched filesystem for document and media files using PowerShell

**Criteria:** powershell.exe executing (Get-)ChildItem


### Detection Type:Telemetry(Correlated)

**Query ID:10C87900-CC2F-4EE1-A2F2-1832A761B050**

df = spark.sql(
'''
SELECT b.ScriptBlockText
FROM apt29Host a
INNER JOIN (
  SELECT d.ParentProcessGuid, d.ProcessId, c.ScriptBlockText
  FROM apt29Host c
  INNER JOIN (
      SELECT ParentProcessGuid, ProcessGuid, ProcessId
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
      ) d
  ON c.ExecutionProcessID = d.ProcessId
  WHERE c.Channel = "Microsoft-Windows-PowerShell/Operational"
          AND c.EventID = 4104
          AND LOWER(c.ScriptBlockText) LIKE "%childitem%"
) b
ON a.ProcessGuid = b.ParentProcessGuid
WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
          AND a.EventID = 1
          AND LOWER(a.ParentImage) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:26F6963D-00D5-466A-B4BA-59DA30892B26**

df = spark.sql(
'''
SELECT b.ScriptBlockText
FROM apt29Host a
INNER JOIN (
  SELECT d.NewProcessId, d.ProcessId, c.ScriptBlockText
  FROM apt29Host c
  INNER JOIN (
      SELECT split(NewProcessId, '0x')[1] as NewProcessId, ProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
      ) d
  ON hex(c.ExecutionProcessID) = d.NewProcessId
  WHERE c.Channel = "Microsoft-Windows-PowerShell/Operational"
          AND c.EventID = 4104
          AND LOWER(c.ScriptBlockText) LIKE "%childitem%"
) b
ON a.NewProcessId = b.ProcessId
WHERE LOWER(a.Channel) = "security"
          AND a.EventID = 4688
          AND LOWER(a.ParentProcessName) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 2.A.2. Automated Collection
**Procedure:** Scripted search of filesystem for document and media files using PowerShell

**Criteria:** powershell.exe executing (Get-)ChildItem


### Detection Type:Telemetry(Correlated)

**Query ID:F96EA21C-1EB4-4988-8F98-BD018717EE2D**

df = spark.sql(
'''
SELECT b.ScriptBlockText
FROM apt29Host a
INNER JOIN (
  SELECT d.ParentProcessGuid, d.ProcessId, c.ScriptBlockText
  FROM apt29Host c
  INNER JOIN (
      SELECT ParentProcessGuid, ProcessGuid, ProcessId
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
      ) d
  ON c.ExecutionProcessID = d.ProcessId
  WHERE c.Channel = "Microsoft-Windows-PowerShell/Operational"
          AND c.EventID = 4104
          AND LOWER(c.ScriptBlockText) LIKE "%childitem%"
) b
ON a.ProcessGuid = b.ParentProcessGuid
WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
          AND a.EventID = 1
          AND LOWER(a.ParentImage) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:EAD989D4-8886-46DC-BC8C-780C10760E93**

df = spark.sql(
'''
SELECT b.ScriptBlockText
FROM apt29Host a
INNER JOIN (
  SELECT d.NewProcessId, d.ProcessId, c.ScriptBlockText
  FROM apt29Host c
  INNER JOIN (
      SELECT split(NewProcessId, '0x')[1] as NewProcessId, ProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
      ) d
  ON hex(c.ExecutionProcessID) = d.NewProcessId
  WHERE c.Channel = "Microsoft-Windows-PowerShell/Operational"
          AND c.EventID = 4104
          AND LOWER(c.ScriptBlockText) LIKE "%childitem%"
) b
ON a.NewProcessId = b.ProcessId
WHERE LOWER(a.Channel) = "security"
          AND a.EventID = 4688
          AND LOWER(a.ParentProcessName) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 2.A.3. Data from Local System
**Procedure:** Recursively collected files found in C:\Users\Pam\ using PowerShell

**Criteria:** powershell.exe reading files in C:\Users\Pam\


### Detection Type:None(None)

## 2.A.4. Data Compressed
**Procedure:** Compressed and stored files into ZIP (Draft.zip) using PowerShell

**Criteria:** powershell.exe executing Compress-Archive


### Detection Type:Telemetry(Correlated)

**Query ID:6CDEBEBF-387F-4A40-A4E8-8D4DF3A8F897**

df = spark.sql(
'''
SELECT b.ScriptBlockText
FROM apt29Host a
INNER JOIN (
  SELECT d.ParentProcessGuid, d.ProcessId, c.ScriptBlockText
  FROM apt29Host c
  INNER JOIN (
      SELECT ParentProcessGuid, ProcessGuid, ProcessId
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
      ) d
  ON c.ExecutionProcessID = d.ProcessId
  WHERE c.Channel = "Microsoft-Windows-PowerShell/Operational"
          AND c.EventID = 4104
          AND LOWER(c.ScriptBlockText) LIKE "%compress-archive%"
) b
ON a.ProcessGuid = b.ParentProcessGuid
WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
          AND a.EventID = 1
          AND LOWER(a.ParentImage) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:621F8EE7-E9D8-417C-9FE5-5A0D89C3736A**

df = spark.sql(
'''
SELECT b.ScriptBlockText
FROM apt29Host a
INNER JOIN (
  SELECT d.NewProcessId, d.ProcessId, c.ScriptBlockText
  FROM apt29Host c
  INNER JOIN (
      SELECT split(NewProcessId, '0x')[1] as NewProcessId, ProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
      ) d
  ON hex(c.ExecutionProcessID) = d.NewProcessId
  WHERE c.Channel = "Microsoft-Windows-PowerShell/Operational"
          AND c.EventID = 4104
          AND LOWER(c.ScriptBlockText) LIKE "%compress-archive%"
) b
ON a.NewProcessId = b.ProcessId
WHERE LOWER(a.Channel) = "security"
          AND a.EventID = 4688
          AND LOWER(a.ParentProcessName) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 2.A.5. Data Staged
**Procedure:** Staged files for exfiltration into ZIP (Draft.zip) using PowerShell

**Criteria:** powershell.exe creating the file draft.zip


### Detection Type:Telemetry(Correlated)

**Query ID:76154CEC-1E01-4D3A-B9ED-C78978597C2B**

df = spark.sql(
'''
SELECT TargetFilename
FROM apt29Host a
INNER JOIN (
    SELECT d.ProcessGuid, d.ProcessId
    FROM apt29Host c
    INNER JOIN (
        SELECT ProcessGuid, ProcessId
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
        ) d
    ON c.ExecutionProcessID = d.ProcessId
    WHERE c.Channel = "Microsoft-Windows-PowerShell/Operational"
            AND c.EventID = 4104
            AND LOWER(c.ScriptBlockText) LIKE "%compress-archive%"
) b
ON a.ProcessGuid = b.ProcessGuid
WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
            AND a.EventID = 11
            AND LOWER(a.TargetFilename) LIKE "%zip"

'''
)
df.show(100,truncate = False, vertical = True)

## 2.B.1. Exfiltration Over Command and Control Channel
**Procedure:** Read and downloaded ZIP (Draft.zip) over C2 channel (192.168.0.5 over TCP port 1234)

**Criteria:** The rcs.3aka3.doc process reading the file draft.zip while connected to the C2 channel


### Detection Type:None(None)

## 3.A.1. Remote File Copy
**Procedure:** Dropped stage 2 payload (monkey.png) to disk

**Criteria:** The rcs.3aka3.doc process creating the file monkey.png


### Detection Type:Telemetry(Correlated)

**Query ID:64249901-ADF8-4E5D-8BB4-70540A45E26C**

df = spark.sql(
'''
SELECT b.Message
FROM apt29Host a
INNER JOIN (
    SELECT ProcessGuid, Message
    FROM apt29Host
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 11
        AND LOWER(TargetFilename) LIKE '%monkey.png'
) b
ON a.ProcessGuid = b.ProcessGuid
WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND a.EventID = 1
  AND LOWER(a.Image) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 3.A.2. Obfuscated Files or Information
**Procedure:** Embedded PowerShell payload in monkey.png using steganography

**Criteria:** Evidence that a PowerShell payload was within monkey.png


### Detection Type:Telemetry(None)

**Query ID:0F10E1D1-EDF8-4B9F-B879-3651598D528A**

df = spark.sql(
'''
SELECT d.Image, d.CommandLine, c.ScriptBlockText
FROM apt29Host c
INNER JOIN (
    SELECT ParentProcessGuid, ProcessGuid, ProcessId, ParentImage, Image, ParentCommandLine, CommandLine
    FROM apt29Host
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 1
    ) d
ON c.ExecutionProcessID = d.ProcessId
WHERE c.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND c.EventID = 4104
    AND LOWER(c.ScriptBlockText) LIKE "%monkey.png%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:94F9B4F2-1C52-4A47-BF47-C786513A05AA**

df = spark.sql(
'''
SELECT d.NewProcessName, d.CommandLine, c.ScriptBlockText
FROM apt29Host c
INNER JOIN (
    SELECT NewProcessName, CommandLine, split(NewProcessId, '0x')[1] as NewProcessId
    FROM apt29Host
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
    ) d
ON LOWER(hex(c.ExecutionProcessID)) = d.NewProcessId
WHERE c.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND c.EventID = 4104
    AND LOWER(c.ScriptBlockText) LIKE "%monkey.png%"

'''
)
df.show(100,truncate = False, vertical = True)

## 3.B.1. Component Object Model Hijacking
**Procedure:** Modified the Registry to enable COM hijacking of sdclt.exe using PowerShell

**Criteria:** Addition of the DelegateExecute ​subkey in ​HKCU\Software\Classes\Folder\shell\open\​​command​​


### Detection Type:Telemetry(None)

**Query ID:04EB334D-A304-40D9-B177-0BB6E95FC23E**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 13
    AND LOWER(TargetObject) RLIKE '.*\\\\\\\\folder\\\\\\\\shell\\\\\\\\open\\\\\\\\command\\\\\\\delegateexecute.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 3.B.2. Bypass User Account Control
**Procedure:** Executed elevated PowerShell payload

**Criteria:** High integrity powershell.exe spawning from control.exe​​ (spawned from sdclt.exe)


### Detection Type:Telemetry(None)

**Query ID:6C8780E9-E6AF-4210-8EA0-72E9017CEE7D**

df = spark.sql(
'''
SELECT Message
FROM apt29Host a
INNER JOIN (
    SELECT ProcessGuid
    FROM apt29Host
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 1
        AND LOWER(Image) LIKE "%control.exe"
        AND LOWER(ParentImage) LIKE "%sdclt.exe"
) b
ON a.ParentProcessGuid = b.ProcessGuid
WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND a.EventID = 1
    AND a.IntegrityLevel = "High"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:EE34D18C-0549-4AFB-8B98-01160B0C9094**

df = spark.sql(
'''
SELECT Message
FROM apt29Host a
INNER JOIN (
    SELECT NewProcessId
    FROM apt29Host
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
        AND LOWER(NewProcessName) LIKE "%control.exe"
        AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
) b
ON a.ProcessId = b.NewProcessId
WHERE LOWER(a.Channel) = "security"
    AND a.EventID = 4688
    AND a.MandatoryLabel = "S-1-16-12288"
    AND a.TokenElevationType = "%%1937"

'''
)
df.show(100,truncate = False, vertical = True)

## 3.B.3. Commonly Used Port
**Procedure:** Established C2 channel (192.168.0.5) via PowerShell payload over TCP port 443

**Criteria:** Established network channel over port 443


### Detection Type:Telemetry(Correlated)

**Query ID:E209D0C5-5A2B-4AEC-92B0-1510165B8EC7**

df = spark.sql(
'''
SELECT Message
FROM apt29Host d
INNER JOIN (
    SELECT a.ProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
) c
ON d.ProcessGuid = c.ProcessGuid
WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 3

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:2E9B9ADC-2426-419F-8E6E-2D9338384F80**

df = spark.sql(
'''
SELECT Message
FROM apt29Host d
INNER JOIN (
    SELECT split(a.NewProcessId, '0x')[1] as NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
) c
ON LOWER(hex(CAST(ProcessId as INT))) = c.NewProcessId
WHERE LOWER(Channel) = "security"
    AND d.EventID = 5156

'''
)
df.show(100,truncate = False, vertical = True)

## 3.B.4. Standard Application Layer Protocol
**Procedure:** Used HTTPS to transport C2 (192.168.0.5) traffic

**Criteria:** Evidence that the network data sent over the C2 channel is HTTPS


### Detection Type:None(None)

## 3.B.5. Standard Cryptographic Protocol
**Procedure:** Used HTTPS to encrypt C2 (192.168.0.5) traffic

**Criteria:** Evidence that the network data sent over the C2 channel is encrypted


### Detection Type:None(None)

## 3.C.1. Modify Registry
**Procedure:** Modified the Registry to remove artifacts of COM hijacking

**Criteria:** Deletion of of the HKCU\Software\Classes\Folder\shell\Open\command subkey


### Detection Type:Telemetry(Correlated)

**Query ID:22A46621-7A92-48C1-81BF-B3937EB4FDC3**

df = spark.sql(
'''
SELECT Message
FROM apt29Host d
INNER JOIN (
    SELECT b.ProcessGuid
    FROM apt29Host b
    INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(ParentImage) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'
    ) a
    ON b.ParentProcessGuid = a.ProcessGuid
    WHERE b.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND b.EventID = 1
) c
ON d.ProcessGuid = c.ProcessGuid
WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND d.EventID = 12
  AND LOWER(d.TargetObject) RLIKE '.*\\\\\\\\folder\\\\\\\\shell\\\\\\\\open\\\\\\\\command.*'
  AND d.Message RLIKE '.*EventType: DeleteKey.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 4.A.1. Remote File Copy
**Procedure:** Dropped additional tools (SysinternalsSuite.zip) to disk over C2 channel (192.168.0.5)

**Criteria:** powershell.exe creating the file SysinternalsSuite.zip


### Detection Type:Telemetry(Correlated)

**Query ID:337EA65D-55A7-4890-BB2A-6A08BB9703E2**

df = spark.sql(
'''
SELECT Message
FROM apt29Host d
INNER JOIN (
    SELECT b.ProcessGuid
    FROM apt29Host b
    INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(ParentImage) RLIKE '.*\\â€Ž|â€|â€ª|â€«|â€¬|â€|â€®.*'
    ) a
    ON b.ParentProcessGuid = a.ProcessGuid
    WHERE b.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND b.EventID = 1
) c
ON d.ProcessGuid = c.ProcessGuid
WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND d.EventID = 11
  AND LOWER(d.TargetFilename) LIKE '%.zip'

'''
)
df.show(100,truncate = False, vertical = True)

## 4.A.2. PowerShell
**Procedure:** Spawned interactive powershell.exe

**Criteria:** powershell.exe spawning from powershell.exe


### Detection Type:Telemetry(Correlated)

**Query ID:B86F90BD-716C-4432-AE97-901174F111A8**

df = spark.sql(
'''
SELECT Message
FROM apt29Host d
INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
) c
ON d.ParentProcessGuid= c.ProcessGuid
WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:FA520225-1813-4EF2-BA58-98CB59C897D7**

df = spark.sql(
'''
SELECT Message
FROM apt29Host d
INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
) c
ON d.ProcessId = c.NewProcessId
WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'

'''
)
df.show(100,truncate = False, vertical = True)

## 4.A.3. Deobfuscate/Decode Files or Information
**Procedure:** Decompressed ZIP (SysinternalsSuite.zip) file using PowerShell

**Criteria:** powershell.exe executing Expand-Archive


### Detection Type:Telemetry(Correlated)

**Query ID:09F29912-8E93-461E-9E89-3F06F6763383**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessId
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND f.EventID = 4104
    AND LOWER(f.ScriptBlockText) LIKE "%expand-archive%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:4310F2AF-11EF-4EAC-A968-3436FE5F6140**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
    FROM apt29Host d
    INNER JOIN(
      SELECT a.ProcessId, a.NewProcessId
      FROM apt29Host a
      INNER JOIN (
        SELECT NewProcessId
        FROM apt29Host
        WHERE LOWER(Channel) = "security"
            AND EventID = 4688
            AND LOWER(NewProcessName) LIKE "%control.exe"
            AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
      ) b
      ON a.ProcessId = b.NewProcessId
      WHERE LOWER(a.Channel) = "security"
        AND a.EventID = 4688
        AND a.MandatoryLabel = "S-1-16-12288"
        AND a.TokenElevationType = "%%1937"
    ) c
    ON d.ProcessId = c.NewProcessId
    WHERE LOWER(d.Channel) = "security"
      AND d.EventID = 4688
      AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND f.EventID = 4104
    AND LOWER(f.ScriptBlockText) LIKE "%expand-archive%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.B.1. Process Discovery
**Procedure:** Enumerated current running processes using PowerShell

**Criteria:** powershell.exe executing Get-Process


### Detection Type:Telemetry(Correlated)

**Query ID:CE6D61C3-C3B5-43D2-BD3C-4C1711A822DA**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessId
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND f.EventID = 4104
    AND LOWER(f.ScriptBlockText) LIKE "%get-process%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:294DFB34-1FA8-464D-B85C-F2AE163DB4A9**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
    FROM apt29Host d
    INNER JOIN(
      SELECT a.ProcessId, a.NewProcessId
      FROM apt29Host a
      INNER JOIN (
        SELECT NewProcessId
        FROM apt29Host
        WHERE LOWER(Channel) = "security"
            AND EventID = 4688
            AND LOWER(NewProcessName) LIKE "%control.exe"
            AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
      ) b
      ON a.ProcessId = b.NewProcessId
      WHERE LOWER(a.Channel) = "security"
        AND a.EventID = 4688
        AND a.MandatoryLabel = "S-1-16-12288"
        AND a.TokenElevationType = "%%1937"
    ) c
    ON d.ProcessId = c.NewProcessId
    WHERE LOWER(d.Channel) = "security"
      AND d.EventID = 4688
      AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND f.EventID = 4104
    AND LOWER(f.ScriptBlockText) LIKE "%get-process%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.B.2. File Deletion
**Procedure:** Deleted rcs.3aka3.doc on disk using SDelete

**Criteria:** sdelete64.exe deleting the file rcs.3aka3.doc


### Detection Type:Telemetry(Correlated)

**Query ID:5EED5350-0BFD-4501-8B2D-4CE4F8F9E948**

df = spark.sql(
'''
SELECT f.ProcessGuid
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessId, d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.ParentProcessGuid = e.ProcessGuid
WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND f.EventID = 1
    AND LOWER(f.Image) LIKE '%sdelete%'
    AND LOWER(f.CommandLine) LIKE '%3aka3%'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:59A9AC92-124D-4C4B-A6BF-3121C98677C3**

df = spark.sql(
'''
SELECT Message
FROM apt29Host h
INNER JOIN (
    SELECT f.ProcessGuid
    FROM apt29Host f
    INNER JOIN (
      SELECT d.ProcessId, d.ProcessGuid
      FROM apt29Host d
      INNER JOIN (
        SELECT a.ProcessGuid, a.ParentProcessGuid
        FROM apt29Host a
        INNER JOIN (
          SELECT ProcessGuid
          FROM apt29Host
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
              AND EventID = 1
              AND LOWER(Image) LIKE "%control.exe"
              AND LOWER(ParentImage) LIKE "%sdclt.exe"
        ) b
        ON a.ParentProcessGuid = b.ProcessGuid
        WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
          AND a.EventID = 1
          AND a.IntegrityLevel = "High"
      ) c
      ON d.ParentProcessGuid= c.ProcessGuid
      WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND d.EventID = 1
        AND d.Image LIKE '%powershell.exe'
    ) e
    ON f.ParentProcessGuid = e.ProcessGuid
    WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND f.EventID = 1
      AND LOWER(f.Image) LIKE '%sdelete%'
      AND LOWER(f.CommandLine) LIKE '%3aka3%'
) g
ON h.ProcessGuid = g.ProcessGuid
WHERE h.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND h.EventID in (12,13)
    AND LOWER(h.TargetObject) RLIKE '.*\\\\\\\\software\\\\\\\\sysinternals\\\\\\\\sdelete.*'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:3A1DC1C2-B640-4FCE-A71F-2F65AB060A8C**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON f.ProcessId = e.NewProcessId
WHERE LOWER(f.Channel) = "security"
  AND f.EventID = 4688
  AND LOWER(f.NewProcessName) LIKE '%sdelete%'
  AND LOWER(f.CommandLine) LIKE '%3aka3%'

'''
)
df.show(100,truncate = False, vertical = True)

## 4.B.3. File Deletion
**Procedure:** Deleted Draft.zip on disk using SDelete

**Criteria:** sdelete64.exe deleting the file draft.zip


### Detection Type:Telemetry(Correlated)

**Query ID:02D0BBFB-4BDF-4167-B530-253779745EF7**

df = spark.sql(
'''
SELECT Message, g.CommandLine
FROM apt29Host h
INNER JOIN (
  SELECT f.ProcessGuid, f.CommandLine
  FROM apt29Host f
  INNER JOIN (
    SELECT d.ProcessId, d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
  ) e
  ON f.ParentProcessGuid = e.ProcessGuid
  WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND f.EventID = 1
    AND LOWER(f.Image) LIKE '%sdelete%'
    AND LOWER(f.CommandLine) LIKE '%draft.zip%'
) g
ON h.ProcessGuid = g.ProcessGuid
WHERE h.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND h.EventID = 23

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:719618E8-9EE7-4693-937E-1FD39228DEBC**

df = spark.sql(
'''
SELECT Message
FROM apt29Host h
INNER JOIN (
  SELECT f.ProcessGuid
  FROM apt29Host f
  INNER JOIN (
    SELECT d.ProcessId, d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
  ) e
  ON f.ParentProcessGuid = e.ProcessGuid
  WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND f.EventID = 1
    AND LOWER(f.Image) LIKE '%sdelete%'
    AND LOWER(f.CommandLine) LIKE '%draft.zip%'
) g
ON h.ProcessGuid = g.ProcessGuid
WHERE h.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND h.EventID in (12,13)
  AND LOWER(h.TargetObject) RLIKE '.*\\\\\\\\software\\\\\\\\sysinternals\\\\\\\\sdelete.*'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:5A19E46B-8328-4867-81CF-87518A3784B1**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
SELECT d.NewProcessId
FROM apt29Host d
INNER JOIN(
  SELECT a.ProcessId, a.NewProcessId
  FROM apt29Host a
  INNER JOIN (
    SELECT NewProcessId
    FROM apt29Host
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
        AND LOWER(NewProcessName) LIKE "%control.exe"
        AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
  ) b
  ON a.ProcessId = b.NewProcessId
  WHERE LOWER(a.Channel) = "security"
    AND a.EventID = 4688
    AND a.MandatoryLabel = "S-1-16-12288"
    AND a.TokenElevationType = "%%1937"
) c
ON d.ProcessId = c.NewProcessId
WHERE LOWER(d.Channel) = "security"
  AND d.EventID = 4688
  AND d.NewProcessName LIKE '%powershell.exe'
) e
ON f.ProcessId = e.NewProcessId
WHERE LOWER(f.Channel) = "security"
AND f.EventID = 4688
AND LOWER(f.NewProcessName) LIKE '%sdelete%'
AND LOWER(f.CommandLine) LIKE '%draft.zip'

'''
)
df.show(100,truncate = False, vertical = True)

## 4.B.4. File Deletion
**Procedure:** Deleted SysinternalsSuite.zip on disk using SDelete

**Criteria:** sdelete64.exe deleting the file SysinternalsSuite.zip


### Detection Type:Telemetry(Correlated)

**Query ID:83D62033-105A-4A02-8B75-DAB52D8D51EC**

df = spark.sql(
'''
SELECT Message, g.CommandLine
FROM apt29Host h
INNER JOIN (
  SELECT f.ProcessGuid, f.CommandLine
  FROM apt29Host f
  INNER JOIN (
    SELECT d.ProcessId, d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
  ) e
  ON f.ParentProcessGuid = e.ProcessGuid
  WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND f.EventID = 1
    AND LOWER(f.Image) LIKE '%sdelete%'
    AND LOWER(f.CommandLine) LIKE '%sysinternalssuite.zip%'
) g
ON h.ProcessGuid = g.ProcessGuid
WHERE h.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND h.EventID = 23

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:AC2ECFF0-D817-4893-BDED-F16B837C4DBA**

df = spark.sql(
'''
SELECT Message
FROM apt29Host h
INNER JOIN (
  SELECT f.ProcessGuid
  FROM apt29Host f
  INNER JOIN (
    SELECT d.ProcessId, d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
  ) e
  ON f.ParentProcessGuid = e.ProcessGuid
  WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND f.EventID = 1
    AND LOWER(f.Image) LIKE '%sdelete%'
    AND LOWER(f.CommandLine) LIKE '%sysinternalssuite.zip%'
) g
ON h.ProcessGuid = g.ProcessGuid
WHERE h.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND h.EventID in (12,13)
  AND LOWER(h.TargetObject) RLIKE '.*\\\\\\\\software\\\\\\\\sysinternals\\\\\\\\sdelete.*'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:4D6DE690-E92C-4D60-93E6-8E5C7C4DF143**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
SELECT d.NewProcessId
FROM apt29Host d
INNER JOIN(
  SELECT a.ProcessId, a.NewProcessId
  FROM apt29Host a
  INNER JOIN (
    SELECT NewProcessId
    FROM apt29Host
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
        AND LOWER(NewProcessName) LIKE "%control.exe"
        AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
  ) b
  ON a.ProcessId = b.NewProcessId
  WHERE LOWER(a.Channel) = "security"
    AND a.EventID = 4688
    AND a.MandatoryLabel = "S-1-16-12288"
    AND a.TokenElevationType = "%%1937"
) c
ON d.ProcessId = c.NewProcessId
WHERE LOWER(d.Channel) = "security"
  AND d.EventID = 4688
  AND d.NewProcessName LIKE '%powershell.exe'
) e
ON f.ProcessId = e.NewProcessId
WHERE LOWER(f.Channel) = "security"
AND f.EventID = 4688
AND LOWER(f.NewProcessName) LIKE '%sdelete%'
AND LOWER(f.CommandLine) LIKE '%sysinternalssuite.zip'

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.1. File and Directory Discovery
**Procedure:** Enumerated user's temporary directory path using PowerShell

**Criteria:** powershell.exe executing $env:TEMP


### Detection Type:Telemetry(Correlated)

**Query ID:85BFD73C-875E-4208-AD9E-1922D4D4D991**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%$env:temp%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:D18CF7B9-CBF0-40CE-9D07-12DC83AF3B2F**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%$env:temp%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.2. System Owner/User Discovery
**Procedure:** Enumerated the current username using PowerShell

**Criteria:** powershell.exe executing $env:USERNAME


### Detection Type:Telemetry(Correlated)

**Query ID:A45F53ED-65CB-4739-A4D3-F2B0F08F86F8**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%$env:username%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:6F3D1615-69D6-41C6-90D0-39ACA14941BD**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%$env:username%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.3. System Information Discovery
**Procedure:** Enumerated the computer hostname using PowerShell

**Criteria:** powershell.exe executing $env:COMPUTERNAME


### Detection Type:Telemetry(Correlated)

**Query ID:9B610803-2B27-4DA4-9AAC-C859F48510DA**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%$env:computername%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:1BA09833-CDF3-44BE-86D0-6F5B1C66D151**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%$env:computername%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.4. System Network Configuration Discovery
**Procedure:** Enumerated the current domain name using PowerShell

**Criteria:** powershell.exe executing $env:USERDOMAIN


### Detection Type:Telemetry(Correlated)

**Query ID:1418A09E-BC90-4BC5-A0BC-1ECC4283ACF4**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%$env:userdomain%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:8D215D46-CE33-4CB7-9934-FF9205971570**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%$env:userdomain%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.5. Process Discovery
**Procedure:** Enumerated the current process ID using PowerShell

**Criteria:** powershell.exe executing $PID


### Detection Type:Telemetry(Correlated)

**Query ID:2DBE08DB-BADD-40AD-A037-DEBD29E207C6**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%$pid%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:9CFC783B-2DC8-4A3D-AC7B-2DF890827E2E**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%$pid%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.6. System Information Discovery
**Procedure:** Enumerated the OS version using PowerShell

**Criteria:** powershell.exe executing​ Gwmi Win32_OperatingSystem


### Detection Type:Telemetry(Correlated)

**Query ID:5A2B7006-A887-465F-9D41-AED8F6AECBE1**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%gwmi win32_operatingsystem%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:69A3B3AC-42BE-44F6-A418-C2356894F745**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%gwmi win32_operatingsystem%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.7. Security Software Discovery
**Procedure:** Enumerated anti-virus software using PowerShell

**Criteria:** powershell.exe executing​ Get-WmiObject ...​ -Class AntiVirusProduct


### Detection Type:Telemetry(Correlated)

**Query ID:E1E0849D-1771-438B-9D8F-A67B7EC48B97**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%-class antivirusproduct%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:956D78C8-FCB5-440D-B059-6790F729D02D**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%-class antivirusproduct%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.8. Security Software Discovery
**Procedure:** Enumerated firewall software using PowerShell

**Criteria:** powershell.exe executing Get-WmiObject ...​​ -Class FireWallProduct


### Detection Type:Telemetry(Correlated)

**Query ID:9F924458-73AD-42C8-B98E-0CB4B4355B9B**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%-class firewallproduct%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:B7549913-AF53-4F9A-9C3F-4106578EA5F2**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%-class firewallproduct%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.9. Permission Groups Discovery
**Procedure:** Enumerated user's domain group membership via the NetUserGetGroups API

**Criteria:** powershell.exe executing the NetUserGetGroups API


### Detection Type:technique(alert)

**Query ID:FA458669-1C94-4150-AFFC-A3236FC6B275**

df = spark.sql(
'''
SELECT a.EventTime, o.TargetUserName, o.IpAddress, a.Message
FROM apt29Host o
INNER JOIN (
    SELECT Message, EventTime, SubjectLogonId
    FROM apt29Host
    WHERE lower(Channel) = "security"
        AND EventID = 4661
        AND ObjectType = "SAM_DOMAIN"
        AND SubjectUserName NOT LIKE '%$'
        AND AccessMask = '0x20094'
        AND LOWER(Message) LIKE '%getlocalgroupmembership%'
    ) a
ON o.TargetLogonId = a.SubjectLogonId
WHERE lower(Channel) = "security" 
        AND o.EventID = 4624
        AND o.LogonType = 3

'''
)
df.show(100,truncate = False, vertical = True)

### Detection Type:Telemetry(Correlated)

**Query ID:11827B7C-8010-443C-9116-500289E0ED57**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%netusergetgroups%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:52E7DFEA-05BC-4B81-BFE9-DE6085FA8228**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%netusergetgroups%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.10. Execution through API
**Procedure:** Executed API call by reflectively loading Netapi32.dll

**Criteria:** The NetUserGetGroups API function loaded into powershell.exe from Netapi32.dll


### Detection Type:Telemetry(Correlated)

**Query ID:0B50643F-98FA-4F4A-8E22-9257D85AD7C5**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.ProcessGuid = e.ProcessGuid
WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
AND f.EventID = 7
AND LOWER(f.ImageLoaded) LIKE "%netapi32.dll"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.11. Permission Groups Discovery
**Procedure:** Enumerated user's local group membership via the NetUserGetLocalGroups API

**Criteria:** powershell.exe executing the NetUserGetLocalGroups API


### Detection Type:Telemetry(Correlated)

**Query ID:1CD16ED8-C812-40B1-B968-F0DABFC79DDF**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%netusergetlocalgroups%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:F0AC46E2-63EA-4C8E-AF39-6631444451E5**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%netusergetlocalgroups%"

'''
)
df.show(100,truncate = False, vertical = True)

## 4.C.12. Execution through API
**Procedure:** Executed API call by reflectively loading Netapi32.dll

**Criteria:** The NetUserGetLocalGroups API function loaded into powershelle.exe from Netapi32.dll


### Detection Type:Telemetry(Correlated)

**Query ID:53CEF026-66EF-4B26-B5C9-10D4BBA3F9E8**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.ProcessGuid = e.ProcessGuid
WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
AND f.EventID = 7
AND LOWER(f.ImageLoaded) LIKE "%netapi32.dll"

'''
)
df.show(100,truncate = False, vertical = True)

## 5.A.1. New Service
**Procedure:** Created a new service (javamtsup) that executes a service binary (javamtsup.exe) at system startup

**Criteria:** powershell.exe creating the Javamtsup service


### Detection Type:Telemetry(Correlated)

**Query ID:A16CE10D-6EE3-4611-BE9B-B023F36E2DFF**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
  AND EventID IN (12,13,14)
  AND (LOWER(TargetObject) LIKE "%javamtsup%" OR LOWER(Details) LIKE "%javamtsup%")

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:E76C4174-C24A-4CA3-9EA8-46C5286D3B6F**

df = spark.sql(
'''
SELECT Payload
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId, d.ParentProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4103
  AND LOWER(f.Payload) LIKE "%new-service%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:AA3EF640-2720-4E8A-B86D-DFCF2FDB86BD**

df = spark.sql(
'''
SELECT Payload
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4103
  AND LOWER(f.Payload) LIKE "%new-service%"

'''
)
df.show(100,truncate = False, vertical = True)

## 5.B.1. Registry Run Keys / Startup Folder
**Procedure:** Created a LNK file (hostui.lnk) in the Startup folder that executes on login

**Criteria:** powershell.exe creating the file hostui.lnk in the Startup folder


### Detection Type:Telemetry(Correlated)

**Query ID:611FCA99-97D0-4873-9E51-1C1BA2DBB40D**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.ProcessGuid = e.ProcessGuid
WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND f.EventID = 11
    AND f.TargetFilename RLIKE '.*\\\\\\\\ProgramData\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\Start Menu\\\\\\\\Programs\\\\\\\\StartUp.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 6.A.1. Credentials in Files
**Procedure:** Read the Chrome SQL database file to extract encrypted credentials

**Criteria:** accesschk.exe reading files within %APPDATALOCAL%\Google\chrome\user data\default\


### Detection Type:None(None)

## 6.A.2. Credential Dumping
**Procedure:** Executed the CryptUnprotectedData API call to decrypt Chrome passwords

**Criteria:** accesschk.exe executing the CryptUnprotectedData API


### Detection Type:None(None)

## 6.A.3. Masquerading
**Procedure:** Masqueraded a Chrome password dump tool as accesscheck.exe, a legitimate Sysinternals tool

**Criteria:** Evidence that accesschk.exe is not the legitimate Sysinternals tool


### Detection Type:Telemetry(Correlated)

**Query ID:0A19F9B7-5E17-47E5-8015-29E9ABC09ADC**

df = spark.sql(
'''
SELECT Message
FROM apt29Host h
INNER JOIN (
    SELECT f.ProcessGuid
    FROM apt29Host f
    INNER JOIN (
      SELECT d.ProcessGuid, d.ParentProcessGuid
      FROM apt29Host d
      INNER JOIN (
        SELECT a.ProcessGuid, a.ParentProcessGuid
        FROM apt29Host a
        INNER JOIN (
          SELECT ProcessGuid
          FROM apt29Host
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
              AND EventID = 1
              AND LOWER(Image) LIKE "%control.exe"
              AND LOWER(ParentImage) LIKE "%sdclt.exe"
        ) b
        ON a.ParentProcessGuid = b.ProcessGuid
        WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
          AND a.EventID = 1
          AND a.IntegrityLevel = "High"
      ) c
      ON d.ParentProcessGuid= c.ProcessGuid
      WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND d.EventID = 1
        AND d.Image LIKE '%powershell.exe'
    ) e
    ON f.ParentProcessGuid = e.ProcessGuid
    WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND f.EventID = 1
      AND LOWER(f.Image) LIKE '%accesschk%'
) g
ON h.ProcessGuid = g.ProcessGuid
WHERE h.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 7
    AND LOWER(ImageLoaded) LIKE '%accesschk%'

'''
)
df.show(100,truncate = False, vertical = True)

### Detection Type:General(Correlated)

**Query ID:1FCE98FC-1FF9-41CB-9C25-0235729A2B01**

df = spark.sql(
'''
SELECT Message
FROM apt29Host h
INNER JOIN (
    SELECT f.ProcessGuid
    FROM apt29Host f
    INNER JOIN (
      SELECT d.ProcessGuid, d.ParentProcessGuid
      FROM apt29Host d
      INNER JOIN (
        SELECT a.ProcessGuid, a.ParentProcessGuid
        FROM apt29Host a
        INNER JOIN (
          SELECT ProcessGuid
          FROM apt29Host
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
              AND EventID = 1
              AND LOWER(Image) LIKE "%control.exe"
              AND LOWER(ParentImage) LIKE "%sdclt.exe"
        ) b
        ON a.ParentProcessGuid = b.ProcessGuid
        WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
          AND a.EventID = 1
          AND a.IntegrityLevel = "High"
      ) c
      ON d.ParentProcessGuid= c.ProcessGuid
      WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND d.EventID = 1
        AND d.Image LIKE '%powershell.exe'
    ) e
    ON f.ParentProcessGuid = e.ProcessGuid
    WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND f.EventID = 1
      AND LOWER(f.Image) LIKE '%accesschk%'
) g
ON h.ProcessGuid = g.ProcessGuid
WHERE h.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 7
    AND LOWER(ImageLoaded) LIKE '%accesschk%'

'''
)
df.show(100,truncate = False, vertical = True)

## 6.B.1. Private Keys
**Procedure:** Exported a local certificate to a PFX file using PowerShell

**Criteria:** powershell.exe creating a certificate file exported from the system


### Detection Type:Telemetry(Correlated)

**Query ID:6392C9F1-D975-4F75-8A70-433DEDD7F622**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.ProcessGuid = e.ProcessGuid
WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
AND f.EventID = 11
AND LOWER(f.TargetFilename) LIKE "%.pfx"

'''
)
df.show(100,truncate = False, vertical = True)

## 6.C.1. Credential Dumping
**Procedure:** Dumped password hashes from the Windows Registry by injecting a malicious DLL into Lsass.exe

**Criteria:** powershell.exe injecting into lsass.exe OR lsass.exe reading Registry keys under HKLM:\SAM\SAM\Domains\Account\Users\


### Detection Type:Telemetry(Correlated)

**Query ID:7B2CE2A5-4386-4EED-9A03-9B7D1049C4AE**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessGuid, d.ParentProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.SourceProcessGuid = e.ParentProcessGuid
WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND f.EventID = 8
    AND f.TargetImage LIKE '%lsass.exe'

'''
)
df.show(100,truncate = False, vertical = True)

## 7.A.1. Screen Capture
**Procedure:** Captured and saved screenshots using PowerShell

**Criteria:** powershell.exe executing the CopyFromScreen function from System.Drawing.dll


### Detection Type:Telemetry(Correlated)

**Query ID:3B4E5808-3C71-406A-B181-17B0CE3178C9**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessGuid, d.ParentProcessGuid
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.ProcessGuid = e.ProcessGuid
WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND f.EventID = 7
    AND LOWER(f.ImageLoaded) LIKE "%system.drawing.ni.dll"

'''
)
df.show(100,truncate = False, vertical = True)

### Detection Type:Telemetry(Correlated)

**Query ID:B374D3E7-3580-441F-8D6E-48C40CBA7922**

df = spark.sql(
'''
SELECT Payload
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessId, d.ParentProcessId
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
AND f.EventID = 4103
AND LOWER(f.Payload) LIKE "%copyfromscreen%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:2AA4D448-3893-4F31-9497-0F8E2B7E3CFD**

df = spark.sql(
'''
SELECT Payload
FROM apt29Host f
INNER JOIN (
    SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
    FROM apt29Host d
    INNER JOIN(
      SELECT a.ProcessId, a.NewProcessId
      FROM apt29Host a
      INNER JOIN (
        SELECT NewProcessId
        FROM apt29Host
        WHERE LOWER(Channel) = "security"
            AND EventID = 4688
            AND LOWER(NewProcessName) LIKE "%control.exe"
            AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
      ) b
      ON a.ProcessId = b.NewProcessId
      WHERE LOWER(a.Channel) = "security"
        AND a.EventID = 4688
        AND a.MandatoryLabel = "S-1-16-12288"
        AND a.TokenElevationType = "%%1937"
    ) c
    ON d.ProcessId = c.NewProcessId
    WHERE LOWER(d.Channel) = "security"
      AND d.EventID = 4688
      AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
AND f.EventID = 4103
AND LOWER(f.Payload) LIKE "%copyfromscreen%"

'''
)
df.show(100,truncate = False, vertical = True)

## 7.A.2. Clipboard Data
**Procedure:** Captured clipboard contents using PowerShell

**Criteria:** powershell.exe executing Get-Clipboard


### Detection Type:Telemetry(Correlated)

**Query ID:F4609F7E-C4DB-4327-91D4-59A58C962A02**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId, d.ParentProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
AND f.EventID = 4103
AND LOWER(f.Payload) LIKE "%get-clipboard%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:6EC8D7EB-153B-459A-9333-51208449DB99**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
AND f.EventID = 4103
AND LOWER(f.Payload) LIKE "%get-clipboard%"

'''
)
df.show(100,truncate = False, vertical = True)

## 7.A.3. Input Capture
**Procedure:** Captured user keystrokes using the GetAsyncKeyState API

**Criteria:** powershell.exe executing the GetAsyncKeyState API


### Detection Type:None(None)

## 7.B.1. Data from Local System
**Procedure:** Read data in the user's Downloads directory using PowerShell

**Criteria:** powershell.exe reading files in C:\Users\pam\Downloads\


### Detection Type:None(None)

## 7.B.2. Data Compressed
**Procedure:** Compressed data from the user's Downloads directory into a ZIP file (OfficeSupplies.7z) using PowerShell

**Criteria:** powershell.exe creating the file OfficeSupplies.7z


### Detection Type:Telemetry(Correlated)

**Query ID:BA68938F-7506-4E20-BC06-0B44B535A0B1**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessGuid, d.ParentProcessGuid
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ProcessGuid = e.ProcessGuid
WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND f.EventID = 11
  AND LOWER(f.TargetFilename) LIKE '%officesupplies%'

'''
)
df.show(100,truncate = False, vertical = True)

## 7.B.3. Data Encrypted
**Procedure:** Encrypted data from the user's Downloads directory using PowerShell

**Criteria:** powershell.exe executing Compress-7Zip with the password argument used for encryption


### Detection Type:Telemetry(Correlated)

**Query ID:4C19DDB9-9763-4D1C-9B9D-788ECF193778**

df = spark.sql(
'''
SELECT f.ScriptBlockText
FROM apt29Host f
INNER JOIN (
  SELECT d.ProcessId, d.ParentProcessId
  FROM apt29Host d
  INNER JOIN (
    SELECT a.ProcessGuid, a.ParentProcessGuid
    FROM apt29Host a
    INNER JOIN (
      SELECT ProcessGuid
      FROM apt29Host
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND LOWER(Image) LIKE "%control.exe"
          AND LOWER(ParentImage) LIKE "%sdclt.exe"
    ) b
    ON a.ParentProcessGuid = b.ProcessGuid
    WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND a.EventID = 1
      AND a.IntegrityLevel = "High"
  ) c
  ON d.ParentProcessGuid= c.ProcessGuid
  WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND d.EventID = 1
    AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND f.EventID = 4104
    AND LOWER(f.ScriptBlockText) LIKE "%compress-7zip%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:C670DAFF-B1FD-45B2-9DEB-AC5AEC273EE7**

df = spark.sql(
'''
SELECT f.ScriptBlockText
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
AND f.EventID = 4104
AND LOWER(f.ScriptBlockText) LIKE "%compress-7zip%"

'''
)
df.show(100,truncate = False, vertical = True)

## 7.B.4. Exfiltration Over Alternative Protocol
**Procedure:** Exfiltrated collection (OfficeSupplies.7z) to WebDAV network share using PowerShell

**Criteria:** powershell executing Copy-Item pointing to an attack-controlled WebDav network share (192.168.0.4:80)


### Detection Type:Telemetry(Correlated)

**Query ID:7AAC6658-2B5C-4B4A-B7C9-D42D288D5218**

df = spark.sql(
'''
SELECT f.ScriptBlockText
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessId, d.ParentProcessId
    FROM apt29Host d
    INNER JOIN (
      SELECT a.ProcessGuid, a.ParentProcessGuid
      FROM apt29Host a
      INNER JOIN (
        SELECT ProcessGuid
        FROM apt29Host
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND EventID = 1
            AND LOWER(Image) LIKE "%control.exe"
            AND LOWER(ParentImage) LIKE "%sdclt.exe"
      ) b
      ON a.ParentProcessGuid = b.ProcessGuid
      WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
        AND a.EventID = 1
        AND a.IntegrityLevel = "High"
    ) c
    ON d.ParentProcessGuid= c.ProcessGuid
    WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
      AND d.EventID = 1
      AND d.Image LIKE '%powershell.exe'
) e
ON f.ExecutionProcessID = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND f.EventID = 4104
  AND LOWER(f.ScriptBlockText) LIKE "%copy-item%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:B19F8E16-AA6C-45C1-8A0D-92812830C237**

df = spark.sql(
'''
SELECT f.ScriptBlockText
FROM apt29Host f
INNER JOIN (
  SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
  FROM apt29Host d
  INNER JOIN(
    SELECT a.ProcessId, a.NewProcessId
    FROM apt29Host a
    INNER JOIN (
      SELECT NewProcessId
      FROM apt29Host
      WHERE LOWER(Channel) = "security"
          AND EventID = 4688
          AND LOWER(NewProcessName) LIKE "%control.exe"
          AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
    ) b
    ON a.ProcessId = b.NewProcessId
    WHERE LOWER(a.Channel) = "security"
      AND a.EventID = 4688
      AND a.MandatoryLabel = "S-1-16-12288"
      AND a.TokenElevationType = "%%1937"
  ) c
  ON d.ProcessId = c.NewProcessId
  WHERE LOWER(d.Channel) = "security"
    AND d.EventID = 4688
    AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(f.ExecutionProcessID)) = e.NewProcessId
WHERE f.Channel = "Microsoft-Windows-PowerShell/Operational"
AND f.EventID = 4104
AND LOWER(f.ScriptBlockText) LIKE "%copy-item%"

'''
)
df.show(100,truncate = False, vertical = True)

### Detection Type:technique(Alert)

**Query ID:C10730EA-6345-4934-AA0F-B0EFCA0C4BA6**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND CommandLine RLIKE '.*rundll32.exe.*\\\\\\\\windows\\\\\\\\system32\\\\\\\\davclnt.dll.*DavSetCookie.*'

'''
)
df.show(100,truncate = False, vertical = True)

## 8.A.1. Remote System Discovery
**Procedure:** Enumerated remote systems using LDAP queries

**Criteria:** powershell.exe making LDAP queries over port 389 to the Domain Controller (10.0.0.4)


### Detection Type:Telemetry(Correlated)

**Query ID:C1307FC1-19B7-467B-9705-95147B492CC7**

df = spark.sql(
'''
SELECT f.Message
FROM apt29Host f
INNER JOIN (
SELECT d.ProcessId, d.ParentProcessId
FROM apt29Host d
INNER JOIN (
  SELECT a.ProcessGuid, a.ParentProcessGuid
  FROM apt29Host a
  INNER JOIN (
    SELECT ProcessGuid
    FROM apt29Host
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 1
        AND LOWER(Image) LIKE "%control.exe"
        AND LOWER(ParentImage) LIKE "%sdclt.exe"
  ) b
  ON a.ParentProcessGuid = b.ProcessGuid
  WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND a.EventID = 1
    AND a.IntegrityLevel = "High"
) c
ON d.ParentProcessGuid= c.ProcessGuid
WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND d.EventID = 1
  AND d.Image LIKE '%powershell.exe'
) e
ON f.ProcessId = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND f.EventID = 3
  AND f.DestinationPort = 389

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:542C2E36-0BC0-450B-A34F-C600E9DC396B**

df = spark.sql(
'''
SELECT f.Message
FROM apt29Host f
INNER JOIN (
    SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
    FROM apt29Host d
    INNER JOIN(
      SELECT a.ProcessId, a.NewProcessId
      FROM apt29Host a
      INNER JOIN (
        SELECT NewProcessId
        FROM apt29Host
        WHERE LOWER(Channel) = "security"
            AND EventID = 4688
            AND LOWER(NewProcessName) LIKE "%control.exe"
            AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
      ) b
      ON a.ProcessId = b.NewProcessId
      WHERE LOWER(a.Channel) = "security"
        AND a.EventID = 4688
        AND a.MandatoryLabel = "S-1-16-12288"
        AND a.TokenElevationType = "%%1937"
    ) c
    ON d.ProcessId = c.NewProcessId
    WHERE LOWER(d.Channel) = "security"
      AND d.EventID = 4688
      AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(CAST(f.ProcessId as INT))) = e.NewProcessId
WHERE LOWER(f.Channel) = "security"
    AND EventID = 5156
    AND DestPort = 389

'''
)
df.show(100,truncate = False, vertical = True)

## 8.A.2. Remote System Discovery
**Procedure:** Established WinRM connection to remote host NASHUA (10.0.1.6)

**Criteria:** Network connection to NASHUA (10.0.1.6) over port 5985


### Detection Type:Telemetry(Correlated)

**Query ID:0A5428EA-171D-4944-B27C-0EBC3D557FAD**

df = spark.sql(
'''
SELECT f.Message
FROM apt29Host f
INNER JOIN (
SELECT d.ProcessId, d.ParentProcessId
FROM apt29Host d
INNER JOIN (
  SELECT a.ProcessGuid, a.ParentProcessGuid
  FROM apt29Host a
  INNER JOIN (
    SELECT ProcessGuid
    FROM apt29Host
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 1
        AND LOWER(Image) LIKE "%control.exe"
        AND LOWER(ParentImage) LIKE "%sdclt.exe"
  ) b
  ON a.ParentProcessGuid = b.ProcessGuid
  WHERE a.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND a.EventID = 1
    AND a.IntegrityLevel = "High"
) c
ON d.ParentProcessGuid= c.ProcessGuid
WHERE d.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND d.EventID = 1
  AND d.Image LIKE '%powershell.exe'
) e
ON f.ProcessId = e.ProcessId
WHERE f.Channel = "Microsoft-Windows-Sysmon/Operational"
  AND f.EventID = 3
  AND f.DestinationPort = 5985

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:0376E07E-3C48-4B89-A50D-B3FAAB23EDAB**

df = spark.sql(
'''
SELECT f.Message
FROM apt29Host f
INNER JOIN (
    SELECT split(d.NewProcessId, '0x')[1] as NewProcessId
    FROM apt29Host d
    INNER JOIN(
      SELECT a.ProcessId, a.NewProcessId
      FROM apt29Host a
      INNER JOIN (
        SELECT NewProcessId
        FROM apt29Host
        WHERE LOWER(Channel) = "security"
            AND EventID = 4688
            AND LOWER(NewProcessName) LIKE "%control.exe"
            AND LOWER(ParentProcessName) LIKE "%sdclt.exe"
      ) b
      ON a.ProcessId = b.NewProcessId
      WHERE LOWER(a.Channel) = "security"
        AND a.EventID = 4688
        AND a.MandatoryLabel = "S-1-16-12288"
        AND a.TokenElevationType = "%%1937"
    ) c
    ON d.ProcessId = c.NewProcessId
    WHERE LOWER(d.Channel) = "security"
      AND d.EventID = 4688
      AND d.NewProcessName LIKE '%powershell.exe'
) e
ON LOWER(hex(CAST(f.ProcessId as INT))) = e.NewProcessId
WHERE LOWER(f.Channel) = "security"
    AND EventID = 5156
    AND DestPort = 5985

'''
)
df.show(100,truncate = False, vertical = True)

## 8.A.3. Process Discovery
**Procedure:** Enumerated processes on remote host Scranton (10.0.1.4) using PowerShell

**Criteria:** powershell.exe executing Get-Process


### Detection Type:Telemetry(Correlated)

**Query ID:6C481791-2AE8-4F6B-9BFE-C1F6DE1E0BC0**

df = spark.sql(
'''
SELECT b.ScriptBlockText
FROM apt29Host b
INNER JOIN (
    SELECT ProcessGuid, ProcessId
    FROM apt29Host
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND LOWER(Image) LIKE '%wsmprovhost.exe'
) a
ON b.ExecutionProcessID = a.ProcessId
WHERE b.Channel = "Microsoft-Windows-PowerShell/Operational"
  AND b.EventID = 4104
  AND LOWER(b.ScriptBlockText) LIKE "%get-process%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:088846AF-FF45-4FC4-896C-64F24517BBD7**

df = spark.sql(
'''
SELECT b.ScriptBlockText
FROM apt29Host b
INNER JOIN (
    SELECT split(NewProcessId, '0x')[1] as NewProcessId
    FROM apt29Host
    WHERE LOWER(Channel) = "security"
      AND EventID = 4688
      AND LOWER(NewProcessName) LIKE '%wsmprovhost.exe'
) a
ON LOWER(hex(b.ExecutionProcessID)) = a.NewProcessId
WHERE b.Channel = "Microsoft-Windows-PowerShell/Operational"
AND b.EventID = 4104
AND LOWER(b.ScriptBlockText) LIKE "%get-process%"

'''
)
df.show(100,truncate = False, vertical = True)

## 8.B.1. Remote File Copy
**Procedure:** Copied python.exe payload from a WebDAV share (192.168.0.4) to remote host Scranton (10.0.1.4)

**Criteria:** The file python.exe created on Scranton (10.0.1.4)


### Detection Type:Telemetry(None)

**Query ID:97402495-2449-415F-BDAD-5CC8EFC1E1B5**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE LOWER(Channel) = "security"
  AND EventID = 5145
  AND RelativeTargetName LIKE '%python.exe'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:D804F2D8-C65B-42D6-A731-C13BE2BDB441**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = 'Microsoft-Windows-Sysmon/Operational'
    AND EventID = 11
    AND TargetFilename LIKE '%python.exe'

'''
)
df.show(100,truncate = False, vertical = True)

## 8.B.2. Software Packing
**Procedure:** python.exe payload was packed with UPX

**Criteria:** Evidence that the file python.exe is packed


### Detection Type:None(None)

## 8.C.1. Valid Accounts
**Procedure:** Logged on to remote host NASHUA (10.0.1.6) using valid credentials for user Pam

**Criteria:** Successful logon as user Pam on NASHUA (10.0.1.6)


### Detection Type:Telemetry(None)

**Query ID:AF5E8E22-DEC8-40AF-98AD-84BE1AC3F34C**

df = spark.sql(
'''
SELECT Hostname, a.Message
FROM apt29Host b
INNER JOIN (
    SELECT TargetLogonId, Message
    FROM apt29Host
    WHERE LOWER(Channel) = "security"
        AND EventID = 4624
        AND LogonType = 3
        AND TargetUserName NOT LIKE '%$'
) a
ON b.SubjectLogonId = a.TargetLogonId
WHERE LOWER(b.Channel) = "security"
  AND b.EventID = 5145
  AND b.RelativeTargetName LIKE '%python.exe'

'''
)
df.show(100,truncate = False, vertical = True)

## 8.C.2. Windows Admin Shares
**Procedure:** Established SMB session to remote host NASHUA's (10.0.1.6) IPC$ share using PsExec

**Criteria:** SMB session to NASHUA (10.0.1.6) over TCP port 445/135 OR evidence of usage of a Windows share


### Detection Type:Telemetry(None)

**Query ID:C91A4BF2-22B1-421B-B1DE-626778AD3BBB**

df = spark.sql(
'''
SELECT EventTime, Hostname, ShareName, RelativeTargetName, SubjectUserName
FROM apt29Host
WHERE LOWER(Channel) = "security"
  AND EventID = 5145
  AND ShareName LIKE '%IPC%'
  AND RelativeTargetName LIKE '%PSEXESVC%'

'''
)
df.show(100,truncate = False, vertical = True)

## 8.C.3. Service Execution
**Procedure:** Executed python.exe using PSExec

**Criteria:** python.exe spawned by PSEXESVC.exe


### Detection Type:Telemetry(Correlated)

**Query ID:BDE98B9B-77DD-4AD4-B755-463C3C27EE5F**

df = spark.sql(
'''
SELECT Message
FROM apt29Host b
INNER JOIN (
    SELECT ProcessGuid
    FROM apt29Host
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 1
        AND ParentImage LIKE '%services.exe'
) a
ON b.ParentProcessGuid = a.ProcessGuid
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND Image LIKE '%python.exe'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:11D81CCD-163F-4347-8F1D-072F4B4B3B26**

df = spark.sql(
'''
SELECT Message
FROM apt29Host b
INNER JOIN (
    SELECT NewProcessId
    FROM apt29Host
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
        AND ParentProcessName LIKE '%services.exe'
) a
ON b.ProcessId = a.NewProcessId
WHERE LOWER(Channel) = "security"
    AND NewProcessName LIKE '%python.exe'

'''
)
df.show(100,truncate = False, vertical = True)

## 9.A.1. Remote File Copy
**Procedure:** Dropped rar.exe to disk on remote host NASHUA (10.0.1.6)

**Criteria:** python.exe creating the file rar.exe


### Detection Type:Telemetry(Correlated)

**Query ID:1C94AFAF-74A9-4578-B026-7AA6948D9DBE**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
        SELECT b.ProcessGuid
        FROM apt29Host b
        INNER JOIN (
          SELECT ProcessGuid
          FROM apt29Host
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
              AND EventID = 1
              AND ParentImage LIKE '%services.exe'
        ) a
        ON b.ParentProcessGuid = a.ProcessGuid
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND Image LIKE '%python.exe'
    ) c
    ON d.ParentProcessGuid = c.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 1
) e
ON f.ProcessGuid = e.ProcessGuid
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 11

'''
)
df.show(100,truncate = False, vertical = True)

## 9.A.2. Remote File Copy
**Procedure:** Dropped rar.exe to disk on remote host NASHUA (10.0.1.6)

**Criteria:** python.exe creating the file sdelete64.exe


### Detection Type:Telemetry(Correlated)

**Query ID:F98D589E-94A9-4974-A142-7E75D9760118**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
        SELECT b.ProcessGuid
        FROM apt29Host b
        INNER JOIN (
          SELECT ProcessGuid
          FROM apt29Host
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
              AND EventID = 1
              AND ParentImage LIKE '%services.exe'
        ) a
        ON b.ParentProcessGuid = a.ProcessGuid
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND Image LIKE '%python.exe'
    ) c
    ON d.ParentProcessGuid = c.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 1
) e
ON f.ProcessGuid = e.ProcessGuid
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 11

'''
)
df.show(100,truncate = False, vertical = True)

## 9.B.1. PowerShell
**Procedure:** Spawned interactive powershell.exe

**Criteria:** powershell.exe​ spawning from python.exe


### Detection Type:Telemetry(Correlated)

**Query ID:77D403CE-2832-4927-B74A-42D965B5AF94**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.ProcessGuid
    FROM apt29Host d
    INNER JOIN (
        SELECT b.ProcessGuid
        FROM apt29Host b
        INNER JOIN (
          SELECT ProcessGuid
          FROM apt29Host
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
              AND EventID = 1
              AND ParentImage LIKE '%services.exe'
        ) a
        ON b.ParentProcessGuid = a.ProcessGuid
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND Image LIKE '%python.exe'
    ) c
    ON d.ParentProcessGuid = c.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND EventID = 1
) e
ON f.ParentProcessGuid = e.ProcessGuid
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND EventID = 1
    AND Image LIKE '%powershell.exe'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:B56C6666-EEF3-4028-85D4-6AAE01CD506C**

df = spark.sql(
'''
SELECT Message
FROM apt29Host f
INNER JOIN (
    SELECT d.NewProcessId
    FROM apt29Host d
    INNER JOIN (
        SELECT b.NewProcessId
        FROM apt29Host b
        INNER JOIN (
          SELECT NewProcessId
          FROM apt29Host
          WHERE LOWER(Channel) = "security"
              AND EventID = 4688
              AND ParentProcessName LIKE '%services.exe'
        ) a
        ON b.ProcessId = a.NewProcessId
        WHERE LOWER(Channel) = "security"
          AND NewProcessName LIKE '%python.exe'
    ) c
    ON d.ProcessId = c.NewProcessId
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
) e
ON f.ProcessId = e.NewProcessId
WHERE LOWER(Channel) = "security"
    AND EventID = 4688
    AND NewProcessName LIKE '%powershell.exe'

'''
)
df.show(100,truncate = False, vertical = True)

## 9.B.2. File and Directory Discovery
**Procedure:** Searched filesystem for document and media files using PowerShell

**Criteria:** powershell.exe executing (Get-)ChildItem​


### Detection Type:Telemetry(Correlated)

**Query ID:3DDF2B9B-10AC-454C-BFA0-1F7BD011947E**

df = spark.sql(
'''
SELECT h.ScriptBlockText
FROM apt29Host h
INNER JOIN (
    SELECT f.ProcessId
    FROM apt29Host f
    INNER JOIN (
      SELECT d.ProcessGuid
      FROM apt29Host d
      INNER JOIN (
          SELECT b.ProcessGuid
          FROM apt29Host b
          INNER JOIN (
            SELECT ProcessGuid
            FROM apt29Host
            WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND EventID = 1
                AND ParentImage LIKE '%services.exe'
          ) a
          ON b.ParentProcessGuid = a.ProcessGuid
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND Image LIKE '%python.exe'
      ) c
      ON d.ParentProcessGuid = c.ProcessGuid
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
    ) e
    ON f.ParentProcessGuid = e.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
      AND EventID = 1
      AND Image LIKE '%powershell.exe'
) g
ON h.ExecutionProcessID = g.ProcessId
WHERE h.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND h.EventID = 4104
    AND LOWER(h.ScriptBlockText) LIKE "%childitem%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:E7ED941E-F3B3-441B-B43D-1F1B194D6303**

df = spark.sql(
'''
SELECT h.ScriptBlockText
FROM apt29Host h
INNER JOIN (
    SELECT split(f.NewProcessId, '0x')[1] as NewProcessId
    FROM apt29Host f
    INNER JOIN (
        SELECT d.NewProcessId
        FROM apt29Host d
        INNER JOIN (
            SELECT b.NewProcessId
            FROM apt29Host b
            INNER JOIN (
              SELECT NewProcessId
              FROM apt29Host
              WHERE LOWER(Channel) = "security"
                  AND EventID = 4688
                  AND ParentProcessName LIKE '%services.exe'
            ) a
            ON b.ProcessId = a.NewProcessId
            WHERE LOWER(Channel) = "security"
              AND NewProcessName LIKE '%python.exe'
        ) c
        ON d.ProcessId = c.NewProcessId
        WHERE LOWER(Channel) = "security"
            AND EventID = 4688
    ) e
    ON f.ProcessId = e.NewProcessId
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
        AND NewProcessName LIKE '%powershell.exe'
) g
ON LOWER(hex(h.ExecutionProcessID)) = g.NewProcessId
WHERE h.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND h.EventID = 4104
    AND LOWER(h.ScriptBlockText) LIKE "%childitem%"

'''
)
df.show(100,truncate = False, vertical = True)

## 9.B.3. Automated Collection
**Procedure:** Scripted search of filesystem for document and media files using PowerShell

**Criteria:** powershell.exe executing (Get-)ChildItem


### Detection Type:Telemetry(Correlated)

**Query ID:6AE2BDBE-48BD-4323-8572-B2214D244013**

df = spark.sql(
'''
SELECT h.ScriptBlockText
FROM apt29Host h
INNER JOIN (
    SELECT f.ProcessId
    FROM apt29Host f
    INNER JOIN (
      SELECT d.ProcessGuid
      FROM apt29Host d
      INNER JOIN (
          SELECT b.ProcessGuid
          FROM apt29Host b
          INNER JOIN (
            SELECT ProcessGuid
            FROM apt29Host
            WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND EventID = 1
                AND ParentImage LIKE '%services.exe'
          ) a
          ON b.ParentProcessGuid = a.ProcessGuid
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND Image LIKE '%python.exe'
      ) c
      ON d.ParentProcessGuid = c.ProcessGuid
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
    ) e
    ON f.ParentProcessGuid = e.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
      AND EventID = 1
      AND Image LIKE '%powershell.exe'
) g
ON h.ExecutionProcessID = g.ProcessId
WHERE h.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND h.EventID = 4104
    AND LOWER(h.ScriptBlockText) LIKE "%childitem%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:6A0DF333-5329-42B5-9AF6-60AB647051CD**

df = spark.sql(
'''
SELECT h.ScriptBlockText
FROM apt29Host h
INNER JOIN (
    SELECT split(f.NewProcessId, '0x')[1] as NewProcessId
    FROM apt29Host f
    INNER JOIN (
        SELECT d.NewProcessId
        FROM apt29Host d
        INNER JOIN (
            SELECT b.NewProcessId
            FROM apt29Host b
            INNER JOIN (
              SELECT NewProcessId
              FROM apt29Host
              WHERE LOWER(Channel) = "security"
                  AND EventID = 4688
                  AND ParentProcessName LIKE '%services.exe'
            ) a
            ON b.ProcessId = a.NewProcessId
            WHERE LOWER(Channel) = "security"
              AND NewProcessName LIKE '%python.exe'
        ) c
        ON d.ProcessId = c.NewProcessId
        WHERE LOWER(Channel) = "security"
            AND EventID = 4688
    ) e
    ON f.ProcessId = e.NewProcessId
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
        AND NewProcessName LIKE '%powershell.exe'
) g
ON LOWER(hex(h.ExecutionProcessID)) = g.NewProcessId
WHERE h.Channel = "Microsoft-Windows-PowerShell/Operational"
    AND h.EventID = 4104
    AND LOWER(h.ScriptBlockText) LIKE "%childitem%"

'''
)
df.show(100,truncate = False, vertical = True)

## 9.B.4. Data from Local System
**Procedure:** Recursively collected files found in C:\Users\Pam\ using PowerShell

**Criteria:** powershell.exe reading files in C:\Users\Pam\


### Detection Type:None(None)

## 9.B.5. Data Staged
**Procedure:** Staged files for exfiltration into ZIP (working.zip in AppData directory) using PowerShell

**Criteria:** powershell.exe creating the file working.zip


### Detection Type:Telemetry(Correlated)

**Query ID:17B04626-D628-4CFC-9EF1-7FF9CD48FF5E**

df = spark.sql(
'''
SELECT h.Message
FROM apt29Host h
INNER JOIN (
    SELECT f.ProcessGuid
    FROM apt29Host f
    INNER JOIN (
      SELECT d.ProcessGuid
      FROM apt29Host d
      INNER JOIN (
          SELECT b.ProcessGuid
          FROM apt29Host b
          INNER JOIN (
            SELECT ProcessGuid
            FROM apt29Host
            WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND EventID = 1
                AND ParentImage LIKE '%services.exe'
          ) a
          ON b.ParentProcessGuid = a.ProcessGuid
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND Image LIKE '%python.exe'
      ) c
      ON d.ParentProcessGuid = c.ProcessGuid
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
    ) e
    ON f.ParentProcessGuid = e.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
      AND EventID = 1
      AND Image LIKE '%powershell.exe'
) g
ON h.ProcessGuid = g.ProcessGuid
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND h.EventID = 11
    AND LOWER(h.TargetFilename) LIKE "%working.zip"

'''
)
df.show(100,truncate = False, vertical = True)

## 9.B.6. Data Encrypted
**Procedure:** Encrypted staged ZIP (working.zip in AppData directory) into working.zip (on Desktop) using rar.exe

**Criteria:** powershell.exe executing rar.exe with the -a parameter for a password to use for encryption


### Detection Type:Telemetry(Correlated)

**Query ID:9EC44B89-9B82-41F2-B11E-D49392853C63**

df = spark.sql(
'''
SELECT h.Message
FROM apt29Host h
INNER JOIN (
    SELECT f.ProcessGuid
    FROM apt29Host f
    INNER JOIN (
      SELECT d.ProcessGuid
      FROM apt29Host d
      INNER JOIN (
          SELECT b.ProcessGuid
          FROM apt29Host b
          INNER JOIN (
            SELECT ProcessGuid
            FROM apt29Host
            WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND EventID = 1
                AND ParentImage LIKE '%services.exe'
          ) a
          ON b.ParentProcessGuid = a.ProcessGuid
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND Image LIKE '%python.exe'
      ) c
      ON d.ParentProcessGuid = c.ProcessGuid
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
    ) e
    ON f.ParentProcessGuid = e.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
      AND EventID = 1
      AND Image LIKE '%powershell.exe'
) g
ON h.ParentProcessGuid = g.ProcessGuid
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND h.EventID = 1
    AND LOWER(h.CommandLine) LIKE "%rar.exe%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:579D025B-DFFB-416B-B07A-A36D9CE1EF93**

df = spark.sql(
'''
SELECT h.Message
FROM apt29Host h
INNER JOIN (
    SELECT f.NewProcessId
    FROM apt29Host f
    INNER JOIN (
        SELECT d.NewProcessId
        FROM apt29Host d
        INNER JOIN (
            SELECT b.NewProcessId
            FROM apt29Host b
            INNER JOIN (
              SELECT NewProcessId
              FROM apt29Host
              WHERE LOWER(Channel) = "security"
                  AND EventID = 4688
                  AND ParentProcessName LIKE '%services.exe'
            ) a
            ON b.ProcessId = a.NewProcessId
            WHERE LOWER(Channel) = "security"
              AND NewProcessName LIKE '%python.exe'
        ) c
        ON d.ProcessId = c.NewProcessId
        WHERE LOWER(Channel) = "security"
            AND EventID = 4688
    ) e
    ON f.ProcessId = e.NewProcessId
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
        AND NewProcessName LIKE '%powershell.exe'
) g
ON h.ProcessId = g.NewProcessId
WHERE LOWER(Channel) = "security"
    AND h.EventID = 4688
    AND LOWER(h.CommandLine) LIKE "%rar.exe%"

'''
)
df.show(100,truncate = False, vertical = True)

## 9.B.7. Data Compressed
**Procedure:** Compressed staged ZIP (working.zip in AppData directory) into working.zip (on Desktop) using rar.exe

**Criteria:** powershell.exe executing rar.exe


### Detection Type:Telemetry(Correlated)

**Query ID:FD1AE986-FD91-4B91-8BCE-42C9295949F7**

df = spark.sql(
'''
SELECT h.Message
FROM apt29Host h
INNER JOIN (
    SELECT f.ProcessGuid
    FROM apt29Host f
    INNER JOIN (
      SELECT d.ProcessGuid
      FROM apt29Host d
      INNER JOIN (
          SELECT b.ProcessGuid
          FROM apt29Host b
          INNER JOIN (
            SELECT ProcessGuid
            FROM apt29Host
            WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND EventID = 1
                AND ParentImage LIKE '%services.exe'
          ) a
          ON b.ParentProcessGuid = a.ProcessGuid
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND Image LIKE '%python.exe'
      ) c
      ON d.ParentProcessGuid = c.ProcessGuid
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
    ) e
    ON f.ParentProcessGuid = e.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
      AND EventID = 1
      AND Image LIKE '%powershell.exe'
) g
ON h.ParentProcessGuid = g.ProcessGuid
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND h.EventID = 1
    AND LOWER(h.CommandLine) LIKE "%rar.exe%"

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:8A865709-E762-4A26-BDEC-A762FB37947B**

df = spark.sql(
'''
SELECT h.Message
FROM apt29Host h
INNER JOIN (
    SELECT f.NewProcessId
    FROM apt29Host f
    INNER JOIN (
        SELECT d.NewProcessId
        FROM apt29Host d
        INNER JOIN (
            SELECT b.NewProcessId
            FROM apt29Host b
            INNER JOIN (
              SELECT NewProcessId
              FROM apt29Host
              WHERE LOWER(Channel) = "security"
                  AND EventID = 4688
                  AND ParentProcessName LIKE '%services.exe'
            ) a
            ON b.ProcessId = a.NewProcessId
            WHERE LOWER(Channel) = "security"
              AND NewProcessName LIKE '%python.exe'
        ) c
        ON d.ProcessId = c.NewProcessId
        WHERE LOWER(Channel) = "security"
            AND EventID = 4688
    ) e
    ON f.ProcessId = e.NewProcessId
    WHERE LOWER(Channel) = "security"
        AND EventID = 4688
        AND NewProcessName LIKE '%powershell.exe'
) g
ON h.ProcessId = g.NewProcessId
WHERE LOWER(Channel) = "security"
    AND h.EventID = 4688
    AND LOWER(h.CommandLine) LIKE "%rar.exe%"

'''
)
df.show(100,truncate = False, vertical = True)

## 9.B.8. Exfiltration Over Command and Control Channel
**Procedure:** Read and downloaded ZIP (working.zip on Desktop) over C2 channel (192.168.0.5 over TCP port 8443)

**Criteria:** python.exe reading the file working.zip while connected to the C2 channel


### Detection Type:None(None)

## 9.C.1. File Deletion
**Procedure:** Deleted rar.exe on disk using SDelete

**Criteria:** sdelete64.exe deleting the file rar.exe


### Detection Type:Telemetry(Correlated)

**Query ID:C20D8999-0B0D-4A50-9CDC-2BAAC4C7B577**

df = spark.sql(
'''
SELECT Message
FROM apt29Host j
INNER JOIN (
    SELECT h.ProcessGuid
    FROM apt29Host h
    INNER JOIN (
        SELECT f.ProcessGuid
        FROM apt29Host f
        INNER JOIN (
          SELECT d.ProcessGuid
          FROM apt29Host d
          INNER JOIN (
              SELECT b.ProcessGuid
              FROM apt29Host b
              INNER JOIN (
                SELECT ProcessGuid
                FROM apt29Host
                WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                    AND EventID = 1
                    AND ParentImage LIKE '%services.exe'
              ) a
              ON b.ParentProcessGuid = a.ProcessGuid
              WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND Image LIKE '%python.exe'
          ) c
          ON d.ParentProcessGuid = c.ProcessGuid
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
              AND EventID = 1
        ) e
        ON f.ParentProcessGuid = e.ProcessGuid
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND Image LIKE '%cmd.exe'
    ) g
    ON h.ParentProcessGuid = g.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND h.EventID = 1
) i
ON j.ProcessGuid = i.ProcessGuid
WHERE j.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND j.EventID = 23

'''
)
df.show(100,truncate = False, vertical = True)

## 9.C.2. File Deletion
**Procedure:** Deleted working.zip (from Desktop) on disk using SDelete

**Criteria:** sdelete64.exe deleting the file \Desktop\working.zip


### Detection Type:Telemetry(Correlated)

**Query ID:CB869916-7BCF-4F9F-8B95-C19B407B91E3**

df = spark.sql(
'''
SELECT Message
FROM apt29Host j
INNER JOIN (
    SELECT h.ProcessGuid
    FROM apt29Host h
    INNER JOIN (
        SELECT f.ProcessGuid
        FROM apt29Host f
        INNER JOIN (
          SELECT d.ProcessGuid
          FROM apt29Host d
          INNER JOIN (
              SELECT b.ProcessGuid
              FROM apt29Host b
              INNER JOIN (
                SELECT ProcessGuid
                FROM apt29Host
                WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                    AND EventID = 1
                    AND ParentImage LIKE '%services.exe'
              ) a
              ON b.ParentProcessGuid = a.ProcessGuid
              WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND Image LIKE '%python.exe'
          ) c
          ON d.ParentProcessGuid = c.ProcessGuid
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
              AND EventID = 1
        ) e
        ON f.ParentProcessGuid = e.ProcessGuid
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND Image LIKE '%cmd.exe'
    ) g
    ON h.ParentProcessGuid = g.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND h.EventID = 1
) i
ON j.ProcessGuid = i.ProcessGuid
WHERE j.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND j.EventID = 23

'''
)
df.show(100,truncate = False, vertical = True)

## 9.C.3. File Deletion
**Procedure:** Deleted working.zip (from AppData directory) on disk using SDelete

**Criteria:** sdelete64.exe deleting the file \AppData\Roaming\working.zip


### Detection Type:Telemetry(Correlated)

**Query ID:59F37185-0BE4-4D81-8B81-FBFBD8055587**

df = spark.sql(
'''
SELECT Message
FROM apt29Host j
INNER JOIN (
    SELECT h.ProcessGuid
    FROM apt29Host h
    INNER JOIN (
        SELECT f.ProcessGuid
        FROM apt29Host f
        INNER JOIN (
          SELECT d.ProcessGuid
          FROM apt29Host d
          INNER JOIN (
              SELECT b.ProcessGuid
              FROM apt29Host b
              INNER JOIN (
                SELECT ProcessGuid
                FROM apt29Host
                WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                    AND EventID = 1
                    AND ParentImage LIKE '%services.exe'
              ) a
              ON b.ParentProcessGuid = a.ProcessGuid
              WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND Image LIKE '%python.exe'
          ) c
          ON d.ParentProcessGuid = c.ProcessGuid
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
              AND EventID = 1
        ) e
        ON f.ParentProcessGuid = e.ProcessGuid
        WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
          AND Image LIKE '%cmd.exe'
    ) g
    ON h.ParentProcessGuid = g.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
        AND h.EventID = 1
) i
ON j.ProcessGuid = i.ProcessGuid
WHERE j.Channel = "Microsoft-Windows-Sysmon/Operational"
    AND j.EventID = 23

'''
)
df.show(100,truncate = False, vertical = True)

## 9.C.4. File Deletion
**Procedure:** Deleted SDelete on disk using cmd.exe del command

**Criteria:** cmd.exe deleting the file sdelete64.exe


### Detection Type:Telemetry(Correlated)

**Query ID:0FC62E32-9052-49EB-A5D5-1DF316D634AD**

df = spark.sql(
'''
SELECT h.Message
FROM apt29Host h
INNER JOIN (
    SELECT f.ProcessGuid
    FROM apt29Host f
    INNER JOIN (
      SELECT d.ProcessGuid
      FROM apt29Host d
      INNER JOIN (
          SELECT b.ProcessGuid
          FROM apt29Host b
          INNER JOIN (
            SELECT ProcessGuid
            FROM apt29Host
            WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
                AND EventID = 1
                AND ParentImage LIKE '%services.exe'
          ) a
          ON b.ParentProcessGuid = a.ProcessGuid
          WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
            AND Image LIKE '%python.exe'
      ) c
      ON d.ParentProcessGuid = c.ProcessGuid
      WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
          AND EventID = 1
    ) e
    ON f.ParentProcessGuid = e.ProcessGuid
    WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
      AND EventID = 1
      AND Image LIKE '%cmd.exe'
) g
ON h.ProcessGuid = g.ProcessGuid
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
    AND h.EventID = 23

'''
)
df.show(100,truncate = False, vertical = True)

## 10.A.1. Service Execution
**Procedure:** Executed persistent service (javamtsup) on system startup

**Criteria:** javamtsup.exe spawning from services.exe


### Detection Type:Telemetry(None)

**Query ID:CB9F90C0-93EA-469A-9515-7DF27DF1592A**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE Channel = "Microsoft-Windows-Sysmon/Operational"
  AND EventID = 1
  AND ParentImage LIKE '%services.exe'
  AND Image LIKE '%javamtsup.exe'

'''
)
df.show(100,truncate = False, vertical = True)

**Query ID:4DABE602-E648-4C1E-81B3-A2AC96F94CE0**

df = spark.sql(
'''
SELECT Message
FROM apt29Host
WHERE LOWER(Channel) = "security"
  AND EventID = 4688
  AND ParentProcessName LIKE '%services.exe'
  AND NewProcessName LIKE '%javamtsup.exe'

'''
)
df.show(100,truncate = False, vertical = True)

## 10.B.1. Registry Run Keys / Startup Folder
**Procedure:** Executed LNK payload (hostui.lnk) in Startup Folder on user login

**Criteria:** Evidence that the file hostui.lnk (which executes hostui.bat as a byproduct) was executed from the Startup Folder


### Detection Type:None(None)

## 10.B.2. Execution through API
**Procedure:** Executed PowerShell payload via the CreateProcessWithToken API

**Criteria:** hostui.exe executing the CreateProcessWithToken API


### Detection Type:None(None)

## 10.B.3. Access Token Manipulation
**Procedure:** Manipulated the token of the PowerShell payload via the CreateProcessWithToken API

**Criteria:** hostui.exe manipulating the token of powershell.exe via the CreateProcessWithToken API OR powershell.exe executing with the stolen token of explorer.exe


### Detection Type:None(None)