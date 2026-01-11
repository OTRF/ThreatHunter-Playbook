---
name: hunt-data-source-identification
description: Identify relevant security data sources that could capture the behavior defined in a structured hunt hypothesis. Use this skill after the hunt focus has been defined to translate investigative intent into candidate telemetry sources using existing platform catalogs. This skill supports hunt planning by reasoning over available schemas and metadata before analytics development or query execution.
metadata:
  short-description: Identify relevant data sources for hunt planning
---

# Identify Relevant Data Sources

This skill translates a structured hunt hypothesis into a set of **candidate data sources**
that could realistically capture the behavior being investigated.

It is executed **after** the hunt focus has been defined and **before** analytics are written
or queries are executed.

## Workflow

- You MUST complete each step in order and MUST NOT proceed until the current step is complete.
- You MUST NOT read reference documents unless the current step explicitly instructs you to do so.
- You MUST NOT write queries or perform data analysis in this skill.
- Do NOT introduce new research about system internals or adversary tradecraft.

### Step 1: Interpret the Hunt Focus

Understand the investigative intent defined by the hunt hypothesis.

- Review the structured hunt hypothesis.
- Identify:
  - The attack behavior being investigated
  - The platform context (e.g., Windows, Cloud)
  - The type of activity that must be observable (e.g., configuration changes, execution, authentication)
- Do NOT infer specific data tables yet.

This step is complete when the expected *observable activity* is clearly understood
at a conceptual level. Do NOT read reference documents during this step.

### Step 2: Discover Candidate Data Sources

Identify data sources that could capture the expected activity.

- Use `MS Sentinel.search_tables` to perform a **semantic search** over the telemetry catalog.
- Search using:
  - The hunt hypothesis
  - Descriptions of the expected behavior
  - Relevant platform or activity keywords
- Do NOT search for data sources using specific table names.
- Review returned table descriptions and schemas to assess relevance.

This step reasons over schemas and metadata available in the data lake catalog and does
not assert that data is currently flowing, complete, or retained.

Do NOT write queries or validate detections in this step.
Do NOT read reference documents during this step.

### Step 3: Refine and Validate Relevance

Narrow the list of candidate data sources.

- Select tables that:
  - Are plausibly able to capture the expected behavior
  - Expose schema elements aligned with the observable activity
- Explicitly note:
  - Conceptual coverage limitations based on available schemas
  - Planning-level assumptions inferred from table names, descriptions, and schema semantics
- Surface gaps where expected categories of telemetry do not appear to be represented.

### Step 4: Produce Data Source Summary

Produce a final summary using the following documents within this step ONLY.

- Structure the output using `references/data-source-summary-template.md`.
- Do NOT include queries, filters, validation steps, or execution logic.