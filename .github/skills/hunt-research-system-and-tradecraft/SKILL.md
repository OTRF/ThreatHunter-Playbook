---
name: hunt-research-system-and-tradecraft
description: Research system internals and adversary tradecraft to ground a threat hunt in real system behavior and realistic abuse patterns. Use this skill at the start of hunt planning, when you are given a high-level hunt topic but lack a clear understanding of how the system normally operates or how adversaries are known to abuse it. This skill informs early hunt direction by producing candidate abuse patterns, key assumptions, and cited sources, and should be used before defining a concrete hunt hypothesis or selecting data sources.
metadata:
  short-description: Research system internals and adversary tradecraft for hunt planning
---

# Research System Internals and Adversary Tradecraft

Provide structured research context at the start of a threat hunt by incrementally applying only the references explicitly called for in each workflow step. This skill establishes a grounded understanding of system capabilities and adversary behaviors so downstream hunt planning reflects how the environment actually works and how it is realistically abused.

## Workflow

- You MUST complete each step in order and MUST NOT proceed until the current step is complete.
- You MUST NOT read reference documents or perform web searches unless the current step explicitly instructs you to do so.
- Do NOT output raw notes, coverage checks, intermediate reasoning, or step summaries.
- Do NOT restate findings from previous steps outside the final report structure.

### Step 1: Normalize the input

Translate the user's high-level topic into a precise research scope before any investigation begins. This step exists to remove ambiguity and establish a shared frame for system and adversary analysis.

This step is complete only when the scope is explicit and unambiguous.

- Record the topic exactly as provided (e.g., "WMI abuse", "Kerberos abuse").
- Identify the concrete platform, system, or feature in scope.
- Resolve ambiguity by stating explicit assumptions when needed.
- Set the research intent to cover both normal system behavior and adversary abuse unless the user explicitly restricts it.
- If critical scope details are missing or ambiguous, request clarification from the user.
- If sufficient information is available, proceed without further confirmation.

Do NOT perform web searches or read reference documents during this step.

### Step 2: Research system internals

Build a grounded understanding of how the system functions under normal conditions.

- Start with searching the web using `Tavily:tavily-search`, and do not exceed **5 total web search queries** in this step.
- Stop searching once core system concepts, capabilities, and observability are sufficiently understood.
- Apply guidance from `references/tavily-search-guide.md`.
- Collect raw research notes focused on system behavior and capabilities.

During this step only:
- Evaluate coverage using `references/system-internals-research-guide.md` within this step ONLY.
- If gaps are identified, perform targeted follow-up research (web or internal knowledge) and update the notes.

Do NOT read adversary tradecraft reference documents in this step. Do not synthesize or summarize findings.

### Step 3: Research adversary tradecraft

Analyze how adversaries leverage or manipulate the system capabilities identified above.

- Start with searching the web using `Tavily:tavily-search`, and do not exceed **5 total web search queries** in this step.
- Stop searching once dominant abuse behaviors and execution patterns are clearly understood.
- Apply guidance from `references/tavily-search-guide.md`.
- Collect raw research notes focused on behavior and outcomes, not tools.

During this step only:
- Evaluate coverage using `references/adversary-tradecraft-research-guide.md` within this step ONLY.
- If gaps are identified, perform targeted follow-up research (web or internal knowledge) and update the notes.

Do Not read system internals reference documents in this step. Do Not synthesize or summarize findings.

### Step 4: Identify candidate abuse patterns

Using the completed adversary tradecraft research, extract concrete abuse patterns that
will guide hypothesis-driven hunting.

- Identify the top 3–5 distinct patterns (or fewer if one clearly dominates).
- For each pattern, record:
  - Adversary behavior
  - System capability or assumption being abused
  - High-level observables or effects
  - Common variations that preserve the same outcome

Porivide the list of patterns if they exist. They must be tool-agnostic and suitable for use in the next hunt-planning step.

### Step 5: Write the research summary

Produce the final structured research artifact using the following documents within this step ONLY.

- Structure the output using `references/research-summary-template.md`.
- Format and cite sources using `references/research-citations-guide.md`.

This step is synthesis only. Do not introduce new research, assumptions, or evidence at this stage.