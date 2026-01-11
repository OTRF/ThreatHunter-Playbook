# Adversary Tradecraft Research Guide

Use this guide to describe how adversaries leverage or manipulate system capabilities to achieve their objectives, independent of specific tools or malware.

The goal is to express tradecraft as **behavior over system capabilities**.

## 1. Tradecraft Overview

Summarize the adversary’s intent with respect to the system.

- Targeted system or capability
- Adversary objective (e.g., access, persistence, lateral movement)
- Why this system enables that objective

## 2. Abused System Capabilities

Map adversary behavior directly to system internals.

- Which system capability is leveraged?
- What assumption or default behavior is relied upon?
- What conditions must be true for the abuse to succeed?

This section should clearly connect tradecraft back to system behavior.

## 3. Execution Patterns

Describe how adversaries operationalize the abuse.

- High-level sequence of actions
- Required access, privileges, or context
- Variations that preserve the same outcome

Avoid naming tools unless they reveal a **distinct execution path or abstraction layer**.

## 4. Observable Effects

Describe how the abuse manifests in the system.

- Behavioral deviations from expected operation
- Artifacts left behind (logs, traffic, state changes)
- Invariants that persist across implementations

Focus on effects, not signatures.

## 5. Common Abuse Patterns

Abstract adversary behavior into repeatable, tool-agnostic abuse patterns.

Each pattern should describe behavior that remains consistent even as tooling, payloads,
or implementations change.

For each pattern, capture:
- Description of the adversary behavior
- System capability or assumption being abused
- Why the pattern is resilient to tool changes

## 6. Detection Leverage Considerations

Identify where defenders gain leverage.

- Points where abstraction collapses
- Tradeoffs between coverage and precision
- Observations that are difficult for attackers to avoid
