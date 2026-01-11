# Hunt Blueprint: [Hunt Name]

## Hypothesis

Provide the structured hunt hypothesis defined during hunt focus definition.

| Field | Description |
|------|-------------|
| **Hypothesis Title** | [Structured hypothesis title] |
| **Hypothesis Explanation** | [1–4 sentences describing the adversary behavior, plausibility, and system alignment] |
| **Platform Context** | [Windows \| Linux \| macOS \| Cloud \| Other] |

---

## Research Context

This section synthesizes prior research to ground the hunt in system behavior and
realistic adversary tradecraft.

### System Internals Summary

This section summarizes how the system behaves under **normal conditions**, focusing
only on aspects relevant to the selected hunt focus.

| Area | Details |
|------|---------|
| **Core Capabilities** | <ul><li>Key system capabilities relevant to the hunt</li><li>Normal operations that enable or constrain behavior</li></ul> |
| **Execution Paths** | <ul><li>Relevant configuration or execution flows</li><li>Components involved under normal conditions</li></ul> |
| **Dependencies & Trust** | <ul><li>Important dependencies, identities, or trust assumptions</li><li>Implicit guarantees the system relies on</li></ul> |
| **Observability** | <ul><li>Where behavior becomes visible (logs, events, APIs)</li><li>Telemetry surfaces relevant to investigations</li></ul> |

### Adversary Tradecraft Summary

This section focuses exclusively on the **selected attack pattern** defined in the hunt
hypothesis, describing how adversaries execute it in practice.

| Area | Details |
|------|---------|
| **Abused Capabilities** | <ul><li>Specific system behaviors or assumptions leveraged to execute this attack pattern</li></ul> |
| **Execution Pattern** | <ul><li>The typical sequence of actions used to carry out this pattern</li><li>Key prerequisites or setup steps required</li></ul> |
| **Known Variations** | <ul><li>Common variations that preserve the same outcome</li><li>Operational flexibility observed for this pattern</li></ul> |
| **Observable Effects** | <ul><li>Artifacts or behaviors produced when this pattern is executed</li><li>Expected changes visible in telemetry</li></ul> |

---

## Candidate Data Sources

This section captures the data sources identified during planning, grounded in schema
semantics rather than data availability.

| Data Source | Role in Hunt | Notes |
|------------|--------------|-------|
| [Table Name] | [What part of the behavior it captures] | [Planning-level assumptions or limitations] |
| [Table Name] | [...] | [...] |

---

## Analytics

This section defines the analytics that model adversary behavior.  
Each analytic captures intent, reasoning, schema grounding, and structure without
executing queries.

---

### Analytic 1: [Analytic Name]

#### Analytic Intent

Describe the adversary behavior this analytic models and how it supports the hunt
hypothesis. Focus on *what the adversary does*, not whether it is suspicious.

#### Data Sources

| Data Source | Role |
|------------|------|
| [Table Name] | [What part of the behavior it captures] |

#### Entities

| Entity | Description |
|------|-------------|
| Process | [How processes participate in the behavior] |
| User | [Role of user context] |
| Host | [Execution or persistence location] |
| Registry Key | [Persistence or configuration element] |

#### Behavioral Model (Graph Perspective)

Describe the behavior using a conceptual, graph-like representation.

Example:

- User → modifies → Registry Key  
- Registry Key → triggers → Process  
- Process → executes on → Host  

Explain how these relationships represent the adversary behavior.

#### Schema Grounding

Map the behavioral model to concrete schema elements.

| Entity | Relevant Fields |
|------|----------------|
| Process | ProcessName, ProcessId, ParentProcessId |
| Registry Key | RegistryKey, RegistryValueName, RegistryValueData |

Include only fields necessary to express the behavior.

#### Query-Style Representation (SQL-like)

This representation is **non-executable** and captures analytic structure only.

```sql
SELECT
  Timestamp,
  Host,
  User,
  ProcessName,
  RegistryKey
FROM DataSource
WHERE
  RegistryKey LIKE '%Run%'
  AND ProcessName IS NOT NULL
```

---

### Analytic 2: [Optional]

Repeat the same structure for additional analytics as needed.  
Hunts typically begin with a small set (for example, up to five analytics).

---

## Assumptions and Gaps

Record planning-level assumptions and known limitations that affect how this hunt
will be executed or interpreted.

### Assumptions

- [Assumption about logging, visibility, configuration, or expected behavior]
- [Assumption carried forward into execution]

### Gaps

- [Telemetry category not represented by available schemas]
- [Known blind spot, limitation, or uncertainty]

These items should inform execution scoping and validation, not assert data availability.

---

## Planning Notes

Capture optional notes to guide execution and iteration.

Examples:
- Potential sources of benign overlap or noise
- Environment-specific nuances
- Considerations for scoping, validation, or follow-on analysis

---

## Execution Readiness

This hunt blueprint consolidates all planning artifacts and is ready to be used for:

- Hunt execution
- Query development
- Validation and refinement
- Knowledge reuse across future hunts

No execution results, detections, thresholds, or validation outcomes are included in this document.