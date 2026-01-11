# Candidate Data Sources

## Hunt Context
- **Attack Pattern**: [From hunt hypothesis]
- **Platform**: [Windows | Linux | macOS | Cloud | Other]

## Candidate Data Sources

### [Data Source Name]
- **Purpose**: What type of activity this data source is designed to capture
- **Relevant Schema Elements**: High-level fields or concepts exposed by the schema
  (e.g., process execution, registry changes, authentication context)
- **Why It’s Relevant**: How this data source conceptually aligns with the hunt
  hypothesis and expected observable behavior

Repeat this section for each candidate data source.

## Gaps and Assumptions

Document **planning-level gaps and assumptions** identified during data source discovery,
based on schemas and metadata available in the Microsoft Sentinel data lake catalog.

- **Gaps**: Expected categories of telemetry or event types that do not appear to be
  represented by any available table schemas in the data lake.
- **Assumptions**: Planning-level inferences about what the identified tables are
  intended to represent or capture, based on table names, descriptions, and schema
  semantics. These assumptions do not imply that data is currently flowing, complete,
  or retained, and are validated later during hunt execution.

This section makes reasoning explicit while avoiding claims about actual data
availability, configuration, or retention.

## Notes

Capture optional observations that may inform later planning steps, such as:
- Potential overlap between candidate data sources
- Ambiguity in schema naming or field semantics
- Considerations that may affect later scoping or validation

Do NOT include queries, data validation steps, or execution logic here.