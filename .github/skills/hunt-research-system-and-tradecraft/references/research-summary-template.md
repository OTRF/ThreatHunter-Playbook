# Research Report: [Insert Research Focus Here]

## Executive Summary
A concise, executive-level summary of the research outcome, readable on its own.

[2–3 sentences capturing: (1) the system or feature, (2) the adversary behaviors examined, and (3) the most important insights for hunt planning.]

## Research Scope and Focus
This section defines the boundaries and purpose of the research without restating conclusions.

- **System / Feature**: [The system, service, or capability examined]
- **Adversary Objective**: [The adversary goals explored]
- **Research Intent**: [What this research enables for hunt planning]

## System Internals Context
This section explains how the system works under normal conditions, focusing only on capabilities and assumptions relevant to security investigations.

- **Core Capabilities**: [What the system can do and what access or actions it enables]
- **Operational Mechanics**: [At least one end-to-end normal operational flow]
- **Dependencies and Trust**: [Key dependencies, identities, or trust assumptions]
- **Observability**: [Where system behavior becomes visible: logs, events, protocols, APIs]

## Adversary Tradecraft Context
This section describes how adversaries leverage or manipulate system capabilities to achieve their objectives, expressed in behavioral terms.

- **Abused Capabilities**: [Which system behaviors or assumptions are exploited]
- **Execution Patterns**: [High-level sequences, prerequisites, and variations]
- **Observable Effects**: [Artifacts or behaviors produced by the abuse]

## Candidate Patterns
This section enumerates the most hunt-relevant abuse patterns derived from the research.

[Provide 3–5 patterns. Each pattern MUST follow the structure below.]

- **[Pattern Name]**
  **Description**: [What the adversary does]
  **Why It Works**: [System capability or assumption being abused]
  **Key Observables**: [High-level behaviors or artifacts]

- **[Pattern Name]**
  **Description**: [...]
  **Why It Works**: [...]
  **Key Observables**: [...]

## Assumptions and Gaps
This section records uncertainty and limitations that affect interpretation or hunt effectiveness.

- **Assumptions**:
  - [Assumption 1]
  - [Assumption 2]
- **Gaps**:
  - [Gap 1]
  - [Gap 2]

## Sources
This section lists all references used to support claims made in the report.
All citations MUST follow the format defined in `references/research-citations-guide.md`.
Each citation represents a single source and must be grouped as a single block.

### System Internals Sources
List sources that support claims about normal system behavior, architecture, or operation.

**Example:**

- **Author(s)**: Microsoft  
  **Title**: "WMI Architecture"  
  **Source**: Microsoft Learn  
  **Date**: 2021-01-07  
  **URL**: https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-architecture

### Adversary Tradecraft Sources
List sources that support claims about adversary behavior, abuse patterns, or techniques.

**Example:**

- **Author(s)**: The MITRE Corporation  
  **Title**: "Windows Management Instrumentation (T1047)"  
  **Source**: MITRE ATT&CK  
  **Date**: n.d.  
  **URL**: https://attack.mitre.org/techniques/T1047/

Each source must support at least one claim made in the report.

---

**Note:** This report is synthesis-only. Do not introduce new research, assumptions, or evidence beyond what was collected during the research steps.