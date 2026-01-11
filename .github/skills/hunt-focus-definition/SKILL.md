---
name: hunt-focus-definition
description: Define a focused hunt hypothesis by synthesizing completed system internals and adversary tradecraft research. Use this skill after research has been completed to narrow a high-level hunt topic into a single, concrete attack pattern with clear investigative intent. This skill produces a structured, testable hypothesis and should be used before selecting data sources, defining environment scope, or developing analytics.
metadata:
  short-description: Define a structured hunt hypothesis
---
# Define Hunt Focus

This skill synthesizes completed research on system internals and adversary tradecraft into a single, focused hypothesis that defines what specific attack pattern will be investigated in the hunt.

It is executed after research has been completed and before detailed hunt planning, environment scoping, or query development.

## Workflow

- You MUST complete each step in order and MUST NOT proceed until the current step is complete.
- You MUST NOT perform new web searches or introduce new research in this skill.

### Step 1: Synthesize Research Context

Establish the context required to define a focused hunt hypothesis using the outputs of prior research.

- Use the provided hunt research context.
- Draw only from:
  - System internals research findings
  - Adversary tradecraft research findings
  - Identified candidate abuse patterns
- Do NOT read additional reference documents or perform new research.

This step is complete when there is sufficient context to reason about a concrete, observable attack pattern.

### Step 2: Select a Single Attack Pattern

Select **one** attack pattern to focus the hunt.

- Choose the pattern that is:
  - Most realistic for the environment
  - Clearly observable based on expected telemetry
  - Actionable for hypothesis-driven investigation
- If multiple patterns exist, select the dominant one.

Do NOT select multiple patterns.

### Step 3: Generate the Hunt Hypothesis

Create a structured hunt hypothesis describing the selected attack pattern.

- Use the format defined in `references/hypothesis-template.md` within this step ONLY.
- Populate all required sections of the template.

Do NOT define time windows, environment scope, data sources, or constraints in this step.  
Those details are defined later when the hunt is assigned to a specific environment or operational context.