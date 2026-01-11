# Research Report: WMI Abuse

  ## Executive Summary

  Windows Management Instrumentation (WMI) provides a core management interface that can query and act on system components locally or remotely. Adversaries abuse these capabilities for
  discovery, remote execution, and persistence, especially via WMI remote protocol and event subscriptions. The most hunt-relevant signals center on WMI-Activity operational logs, WMI
  consumer/filter objects, and wmiprvse.exe-mediated process creation.

  ## Research Scope and Focus

  - System / Feature: Windows Management Instrumentation (WMI), including WMI service (winmgmt), CIM Object Manager (CIMOM), and WMI-Activity logging
  - Adversary Objective: Discovery, remote execution/lateral movement, and persistence via WMI
  - Research Intent: Provide system baseline and abuse patterns to drive hypothesis-based hunts

  ## System Internals Context

  - Core Capabilities: WMI exposes management data and operations via CIM, mediated by the CIMOM and providers to query/operate on system components and classes. It supports local and
    remote management operations via the WMI remote protocol.
  - Operational Mechanics: A management client issues WMI queries/operations (e.g., ExecQuery or method calls) that the WMI service (winmgmt) and provider host (wmiprvse.exe) fulfill
    using providers and repository data.
  - Dependencies and Trust: Remote WMI relies on DCOM or WinRM for network transport; CIMOM and providers assume valid credentials and authorized access to requested classes.
  - Observability: WMI operations emit events in Microsoft-Windows-WMI-Activity/Operational and can be traced via WMI-Activity logging, including event IDs like 5857–5861 that capture
    provider activity and query execution context.

  ## Adversary Tradecraft Context

  - Abused Capabilities: Adversaries leverage WMI’s remote management interface and class methods to execute commands and gather system data; they also exploit WMI’s event subscription
    mechanism to trigger payloads on specific events for persistence.
  - Execution Patterns: Common flows include remote execution via WMI over DCOM/WinRM; invoking Win32_Process.Create for command execution; and creating __EventFilter, __EventConsumer,
    and __FilterToConsumerBinding objects for persistence triggers.
  - Observable Effects: WMI-Activity Operational events, creation/modification of WMI subscription objects in root\subscription, and process creation under wmiprvse.exe with command lines
    inconsistent with baseline admin tooling.

  ## Candidate Patterns

  - Remote WMI Process Execution
    Description: Adversary uses WMI remote protocol to invoke Win32_Process.Create on a target host to execute commands or payloads.
    Why It Works: WMI exposes remote method execution via DCOM/WinRM as a normal management feature.
    Key Observables: WMI-Activity Operational events tied to ExecQuery/ExecMethod; wmiprvse.exe spawning target processes; network use of DCOM (TCP 135) or WinRM (5985/5986).
  - WMI Event Subscription Persistence
    Description: Adversary creates __EventFilter and __EventConsumer objects and binds them to run code on a trigger.
    Why It Works: WMI supports event subscriptions for legitimate automation; subscriptions persist in the WMI repository.
    Key Observables: New or modified __EventFilter, __EventConsumer, __FilterToConsumerBinding in root\subscription; WMI-Activity events around subscription creation; unusual command
    lines embedded in consumer objects.
  - WMI-Based Discovery at Scale
    Description: Adversary runs WQL queries across local/remote systems to enumerate hardware, processes, services, or configurations.
    Why It Works: WMI is designed for querying a unified view of system state via CIM.
    Key Observables: High volume of WMI query events in WMI-Activity Operational; spikes in wmiprvse.exe activity; repeated queries from non-admin or unexpected accounts.

  ## Assumptions and Gaps

  - Assumptions:
      - WMI-Activity/Operational logging is enabled and collected centrally.
      - Remote WMI is reachable in the environment via DCOM or WinRM.
  - Gaps:
      - No environment-specific baseline for normal WMI query volume or known management tooling.
      - Limited source coverage on default logging levels and how often WMI-Activity is disabled in the fleet.

  ## Sources

  ### System Internals Sources

  - Author(s): Microsoft
    Title: "winmgmt"
    Source: Microsoft Learn
    Date: n.d.
    URL: https://learn.microsoft.com/en-us/windows/win32/wmisdk/winmgmt
  - Author(s): Microsoft
    Title: "[MS-WMI]: Overview"
    Source: Microsoft Learn (Open Specifications)
    Date: n.d.
    URL: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/c0088a94-1107-48a5-8d4d-cd16d34de5ef
  - Author(s): NXLog
    Title: "Understanding and auditing WMI"
    Source: NXLog Blog
    Date: n.d.
    URL: https://nxlog.co/news-and-blog/posts/wmi-auditing
  - Author(s): Darkoperator
    Title: "Basics of Tracking WMI Activity - Shell is Only the Beginning"
    Source: Darkoperator Blog
    Date: 2017-10-14
    URL: https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity

  ### Adversary Tradecraft Sources

  - Author(s): The MITRE Corporation
    Title: "Windows Management Instrumentation, Technique T1047"
    Source: MITRE ATT&CK
    Date: n.d.
    URL: https://attack.mitre.org/techniques/T1047/
  - Author(s): The MITRE Corporation
    Title: "Event Triggered Execution: Windows Management Instrumentation Event Subscription (T1546.003)"
    Source: MITRE ATT&CK
    Date: n.d.
    URL: https://attack.mitre.org/techniques/T1546/003/
  - Author(s): Cybersecurity and Infrastructure Security Agency (CISA)
    Title: "Windows Management Instrumentation (T1047)"
    Source: CISA Eviction Strategies Tool
    Date: n.d.
    URL: https://www.cisa.gov/eviction-strategies-tool/info-attack/T1047
  - Author(s): Threat Hunter Playbook
    Title: "WMI Win32_Process Class and Create Method for Remote Execution"
    Source: Threat Hunter Playbook
    Date: n.d.
    URL: https://threathunterplaybook.com/hunts/windows/190810-RemoteWMIExecution/notebook.html