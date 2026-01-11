## Analytic [Number]: [Analytic Name]

### Analytic Intent

Describe the adversary behavior this analytic models and how it relates to the hunt
hypothesis. Focus on *what the adversary is doing*, not whether the behavior is
suspicious or anomalous.

### Data Sources

Identify the data source or sources used by this analytic.  
An analytic may rely on a single table or combine multiple tables to model the behavior.

| Data Source | Role in Analytic |
|------------|------------------|
| [Table name] | What part of the behavior this data source is expected to capture (e.g., registry modification, process execution, authentication context) |
| [Table name] | [Optional additional source and role] |

Add or remove rows as needed.

### Entities Involved

Identify the primary entities represented across the selected data sources.
List only entities that participate directly in the modeled behavior.

Examples:
- Process
- User
- Host
- Registry Key
- File
- IP Address

If multiple data sources are used, entities may appear in different roles depending on
the schema.

### Behavioral Model (Graph Perspective)

Describe the behavior as relationships or sequences between entities using a
conceptual, graph-like view.

Example:
- User → creates → Registry Key  
- Registry Key → launches → Process  
- Process → executes on → Host  

Explain how these relationships represent the adversary behavior.

### Schema Grounding

Map the behavioral model to concrete schema elements.

- **Entity**: Process  
  - Relevant Fields: ProcessName, ProcessId, ParentProcessId
- **Entity**: Registry Key  
  - Relevant Fields: RegistryKey, RegistryValueName, RegistryValueData

Only include fields necessary to express the behavior.

### Query-Style Representation (SQL-like)

Express the analytic intent using SQL-like logic.
This representation is **not executable** and is used only to capture analytic structure.

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

This representation should reflect the behavioral model and schema grounding,
without platform-specific syntax or execution details.