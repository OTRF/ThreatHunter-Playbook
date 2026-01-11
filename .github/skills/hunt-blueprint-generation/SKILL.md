---
name: hunt-blueprint-generation
description: Assemble a complete hunt blueprint by consolidating outputs from prior hunt planning skills into a single, structured plan for execution. Use this skill after system and tradecraft research, hunt focus definition, data source identification, and analytics generation have been completed. This skill is synthesis and packaging only and must not introduce new research, assumptions, or analytics.
metadata:
  short-description: Generate a structured hunt blueprint for execution
---

# Generate Hunt Blueprint

This skill produces a single, structured hunt blueprint that captures the full hunt
planning trajectory in an execution-ready format.

It is executed **after** the following have been completed:

- System internals and adversary tradecraft research  
- Hunt focus definition (structured hypothesis)  
- Candidate data source identification  
- Analytics generation  

This skill is **assembly and synthesis only**. It preserves and organizes outputs from
prior steps without adding new research, new evidence, or new analytic logic.

## Workflow

- You MUST complete each step in order and MUST NOT proceed until the current step is complete.
- You MUST NOT read reference documents unless the current step explicitly instructs you to do so.
- You MUST NOT perform new web searches or introduce new research.
- You MUST NOT generate new analytics, detections, thresholds, or validation logic.
- You MUST only use planning artifacts produced by prior skills.

### Step 1: Normalize Blueprint Inputs

Confirm that all required inputs are available to assemble the hunt blueprint.

Use available planning artifacts, which may include:

- Research summary (system internals and adversary tradecraft)
- Candidate abuse patterns
- Structured hunt hypothesis
- Candidate data source summary
- Analytics summary and per-analytic details

If any critical planning artifact is missing, request it before proceeding.

Do NOT read reference documents during this step.

This step is complete when all required inputs are available.

### Step 2: Assemble Blueprint Content

Populate the hunt blueprint **using the section structure and ordering defined in**
`references/hunt-blueprint-template.md`.

- Preserve wording and intent from prior artifacts where possible.
- Summarize only to reduce redundancy and improve readability.
- Ensure consistency across:
  - Hunt hypothesis and research context
  - Research context and analytics intent
  - Candidate data sources and schema grounding
- Explicitly capture assumptions, gaps, and planning notes.

Do NOT introduce new material or reinterpret prior outputs.

This step is complete when all blueprint sections are populated according to the template.

### Step 3: Refine Blueprint Content (In-Memory)

Refine the assembled blueprint for clarity and readability **without writing it to disk yet**.

Focus on editorial improvements only:

- Improve wording for clarity and conciseness
- Normalize terminology across hypothesis, research, data sources, and analytics
- Ensure behavioral models are expressed using clear, graph-like statements  
  `(entity → relationship → entity)`
- Improve table readability and layout where needed

You MAY:
- Rephrase sentences for clarity
- Improve behavioral model descriptions
- Adjust Markdown structure for readability

You MUST NOT:
- Add or remove sections
- Change analytic intent or behavioral logic
- Introduce new research, assumptions, or analytics
- Write the blueprint to disk

This step is complete when the blueprint reads clearly and consistently.

### Step 4: Validate and Write Blueprint

Validate the refined blueprint and correct issues **before writing** the final file.

Confirm that:

- The hunt hypothesis aligns with research context and the selected attack pattern
- Candidate data sources plausibly support the modeled behaviors
- Each analytic consistently connects:
  - Analytic intent
  - Data sources
  - Entities and behavioral model
  - Schema grounding
  - SQL-like query-style representation
- Behavioral models are readable and graph-like
- Markdown renders correctly with no formatting or encoding issues
- Assumptions and gaps are planning-level only

You MAY:
- Fix Markdown rendering issues (broken tables, malformed lists, encoding artifacts)
- Correct structural violations of the template

You MUST NOT:
- Reword content for clarity
- Change analytic reasoning or behavior models
- Introduce new research, assumptions, analytics, or execution logic

Once validated, write the blueprint to a Markdown file named after the hunt using lowercase
words separated by underscores  
(for example, `windows_registry_persistence_hunt.md`).

This step is complete when the blueprint is written and ready for execution.