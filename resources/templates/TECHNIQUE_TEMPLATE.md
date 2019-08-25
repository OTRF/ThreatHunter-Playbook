# Technique Variation Name

## Playbook Tags

**ID:** [OS+TacticNameFirstFourLetters+YYMMDDHHMM]

**Author:** Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

**References:** Any other related playbook ID

## ATT&CK Tags

**Tactic:** Tactic Name

**Technique:** Technique Name (Technique ID)

## Applies To

## Technical Description

Brief Description

## Permission Required

[Administrator|user|Domain Admin|]

## Hypothesis

Example: Adversaries might be creating new services remotely to execute code and move laterally in my environment

## Attack Simulation Dataset

Example: 

| Environment| Name | Description |
|--------|---------|---------|
| [Shire](https://github.com/Cyb3rWard0g/mordor/tree/acf9f6be6a386783a20139ceb2faf8146378d603/environment/shire) | [empire_invoke_psexec](https://github.com/Cyb3rWard0g/mordor/blob/master/small_datasets/windows/execution/service_execution_T1035/empire_invoke_psexec.md) | A mordor dataset to simulate an adversary creating a service |

## Recommended Data Sources

| Event ID | Event Name | Log Provider | Audit Category | Audit Sub-Category | ATT&CK Data Source |
|---------|---------|----------|----------|---------|---------|
| | | | | | |

## Data Analytics

| FP Rate | Source | Analytic Logic | Description |
|--------|---------|---------|---------|
| [High|Medium|Low] | [Sysmon|Security|PowerShell]  | SQL Like Query | Description of the analytic |

## False Positives

## Detection Blind Spots

## Hunter Notes

* Any additional Notes

## Hunt Output

Examples:

| Category | Type | Name |
|--------|---------|---------|
| Signature | Sigma Rule | [powershell_alternate_powershell_hosts.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/powershell_alternate_powershell_hosts.yml) |
| Signature | Sigma Rule | [sysmon_alternate_powershell_hosts_moduleload.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_alternate_powershell_hosts_moduleload.yml) |
| Signature | Sigma Rule | [sysmon_alternate_powershell_hosts_pipe.yml](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/signatures/sigma/sysmon_alternate_powershell_hosts_pipe.yml) |

## References

* Any Links that were Helpful