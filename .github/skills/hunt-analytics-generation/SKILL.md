---
name: hunt-analytics-generation
description: Generate query-agnostic analytics that model adversary behavior by translating hunt investigative intent into analytic definitions grounded in schema semantics. This skill is used to define how behavior should manifest in data before query execution or validation, and works best when informed by system internals, adversary tradecraft, a structured hunt focus, and suggested data sources.
metadata:
  short-description: Generate analytics for hunt planning
---

# Generating Analytics

This skill translates hunt investigative intent into a small set of analytics that
describe how adversary behavior should manifest in data.

It is executed during hunt planning, after sufficient context has been established,
and before queries are executed or detections are validated.

This skill focuses on **behavior modeling**, not determining what is suspicious or
anomalous, which requires broader environmental context beyond adversary descriptions
or schema inspection.

## Workflow

- You MUST complete each step in order and MUST NOT proceed until the current step is complete.
- You MUST NOT read reference documents unless the current step explicitly instructs you to do so.
- You MUST NOT execute queries or validate results in this skill.
- You MUST NOT introduce new research about system internals or adversary tradecraft.
- You MAY retrieve table schemas using platform tools when explicitly instructed.

### Step 1: Interpret and Normalize Input

Establish the context required to generate analytics.

- Use the available inputs, which may include:
  - System internals context
  - Adversary tradecraft context
  - The structured hunt hypothesis
  - Suggested or identified data sources
- Confirm the specific adversary behavior to be modeled.
- If critical context is missing, request minimal clarification before proceeding.

This step is complete when the behavior to be modeled is clearly understood. Do NOT read reference documents during this step.

### Step 2: Generate Analytic Candidates (repeat up to 5 times)

For each analytic candidate:

- Select the most relevant data source or sources from the available list.
- Use `MS Sentinel.search_tables` to retrieve schema details for the selected tables.
- Review schemas to understand available fields and attributes.
- Identify the key entities involved (e.g., process, user, host, registry key, IP).
- Model the behavior as relationships or sequences between entities, using a graph-like
  view to represent how the activity unfolds and the conditions that matter.
- Ground the logic by mapping entities and conditions to schema fields.
- Capture a query-style representation, using SQL-like logic, that expresses analytic
  intent without execution.

Do NOT determine whether the behavior is suspicious or anomalous.
Do NOT write executable queries.
Do NOT read reference documents during this step.

### Step 3: Produce Analytics Summary

Produce a final summary of the generated analytics.

- Structure the output using `references/analytic-template.md`.
- Repeat the template for each analytic.
- Clearly separate:
  - Behavioral reasoning
  - Schema grounding
  - Query-style representation

Do NOT include execution logic, thresholds, or validation steps.