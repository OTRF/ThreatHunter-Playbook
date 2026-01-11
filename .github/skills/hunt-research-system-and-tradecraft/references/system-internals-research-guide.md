# System Internals Research Guide

Use this guide to understand how a system or feature functions under normal conditions, with enough depth that adversary behavior can later be reasoned about without relying on specific tools.

The goal is to capture **capabilities, assumptions, and observability**, not detections or attacks.

## 1. System Overview

Briefly describe the system or feature and its role in the environment.

- System or feature name
- Primary purpose and responsibilities
- Where it fits architecturally (endpoint, identity, network, cloud control plane, etc.)

## 2. Core Capabilities

Describe what the system is fundamentally capable of doing.

- What actions it can perform
- What resources it can access or modify
- What identities or privileges it can act on behalf of

Focus on *what is possible*, not how it is abused.

## 3. Operational Flow

Explain how the system operates during normal use.

- Key steps or phases in normal operation
- Required inputs or preconditions
- Expected outputs or state changes

This should reflect how the system must behave to accomplish its purpose.

## 4. Dependencies and Trust Assumptions

Document what the system relies on to function.

- External systems or services
- Identity, authentication, or authorization dependencies
- Implicit trust relationships or default assumptions

Highlight dependencies that could influence security outcomes.

## 5. Observability and Telemetry Surfaces

Identify where system behavior becomes observable.

- Logs, events, metrics, traces, or audit records
- APIs, protocols, or message flows
- Operations that must occur even when abstracted by higher layers

Focus on **where behavior leaks**, not on detections.

## 6. Expected Behavior Baseline

Describe what “normal” looks like.

- Typical usage patterns
- Common legitimate variations
- Known benign edge cases

This establishes a baseline for later reasoning about abnormal behavior.