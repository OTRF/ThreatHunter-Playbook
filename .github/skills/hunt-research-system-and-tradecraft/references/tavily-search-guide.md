# Tavily Search Best Practices for Threat Research

This document provides guidelines and best practices for using **Tavily Search** within the context of threat research. It offers a structured approach to leveraging the **Tavily MCP tools** such as **tavily-search**, **tavily-extract**, and **tavily-crawl** during threat hunting activities. These practices are intended to ensure efficient use of the tools and improve the effectiveness of your research.

## Best Practices for Using Tavily Search

### 1) Normalize the Input (Broad Queries)
Start by using broad queries to gather foundational knowledge about the technology or adversary behavior you are researching.

#### Tavily Search Best Practice:
- **Start with broad queries** to identify the general landscape of the topic. For example, if researching **Kerberos abuse**, begin with queries such as:
  - "Kerberos authentication mechanism"
  - "Windows event logging basics"
  - "Kerberos ticket-granting service"
- Use **Tavily Search** to get a general overview before refining the query.

#### Example:
- Query: **"Kerberos authentication"**
- Refine further by adding platform-specific terms later, such as: **"Windows Kerberos event logs"**.

---

### 2) Research System Internals (Narrowing the Focus)
After gathering general knowledge, refine your search to focus specifically on how the system works under normal conditions.

#### Tavily Search Best Practice:
- **Narrow your search** by adding platform-specific terms to get more precise insights into the system internals. For example:
  - "Windows Kerberos event logs"
  - "Kerberos authentication flow in Windows 10"
- Use **Tavily Search**'s filtering options (e.g., by date or source) to focus on the most relevant and recent information.

#### Example:
- Query: **"Windows Kerberos authentication flow"**
- Refined Query: **"Windows 10 Kerberos TGS ticket behavior"**

---

### 3) Research Adversary Tradecraft (Focus on Techniques, Not Tools)
Once you understand how the system works, focus on how adversaries exploit those systems.

#### Tavily Search Best Practice:
- **Narrow your query** to focus on **adversary tactics, techniques, and procedures (TTPs)**.
- Use **Tavily Search** to explore adversary techniques such as **Kerberoasting** or **WMI abuse**.
- Avoid focusing solely on tools. Instead, look for techniques and observable patterns.

#### Example:
- Query: **"Kerberos abuse techniques"**
- Refined Query: **"Kerberoasting offline cracking"**

#### Tip:
- **Focus on techniques** (e.g., "offline cracking," "service account abuse") rather than just tools used in the attack.

---

### 4) Identify Candidate Abuse Patterns
With enough context gathered from system internals and adversary tradecraft, identify abuse patterns that could inform the next phase of your threat hunt.

#### Tavily Search Best Practice:
- **Use Tavily Extract** to extract specific adversary behaviors from reliable sources and document them.
- **Identify top abuse patterns** based on your research, such as:
  - "Kerberos ticket-granting service abuse"
  - "Service account escalation using Kerberos"

#### Example:
- Pattern: **"Ticket-granting service abuse"**
- Pattern: **"Offline cracking of Kerberos tickets"**

#### Tip:
- **Be specific** about the patterns you are identifying. Focus on clear, actionable patterns that are impactful for your hunt.

---

## Advanced Search Strategies

### Broad to Narrow Search
Start with general queries and progressively refine them to get more specific insights.

#### Example:
1. **Broad Search**: "API integration"
2. **Refined Search**: "API integration Windows"
3. **Final Search**: "API integration Kerberos authentication"

**Tip**: Iterating from broad to narrow ensures you focus on the most relevant results, cutting down on noise.

---

### Multi-Query Approach
Running multiple related queries simultaneously helps you capture a broader range of insights and fills gaps in your understanding.

#### Example:
- Query 1: **"Kerberos authentication"**
- Query 2: **"Kerberos ticket-granting service"**
- Query 3: **"Kerberos abuse patterns"**

**Tip**: Multi-query searches are useful when you need to cover different aspects of the topic, ensuring comprehensive research.

---

### Temporal Research (Tracking Changes Over Time)
Search across different time periods to understand how a topic or adversary tradecraft has evolved.

#### Example:
1. **Search 1**: `created_date_range 2023` → Historical context
2. **Search 2**: `created_date_range 2024` → Recent developments
3. **Search 3**: `created_date_range 2025` → Current state

**Tip**: Temporal research helps you track how tactics or techniques have evolved over time, providing insights into trends or new developments.

---

## Result Processing

### Identifying Relevant Results
Look for results that are:
- **Highly relevant** to your query.
- **From authoritative sources** (e.g., vendor documentation, trusted cybersecurity reports).
- **Recent** and offer up-to-date information.

### Prioritizing Fetches
Fetch results in order of relevance:
1. **Primary sources**: Official documentation or authoritative articles.
2. **Recent results**: Newly edited or published content.
3. **Related context**: Supporting information or adjacent research.
4. **Historical reference**: Older references for context.

**Tip**: Be selective when fetching content. Prioritize the most authoritative and up-to-date information.

### Handling Too Many Results
If your search returns too many results:
1. **Refine the query**: Narrow the search further by date, creator, or teamspace.
2. **Use filters**: Apply filters to focus on the most relevant results.
3. **Use page scoping**: Focus on a specific page or section.

### Handling Too Few Results
If your search returns too few results:
1. **Broaden the query**: Use more general or alternative terms.
2. **Remove filters**: Relax some filters to broaden the search.
3. **Try synonyms**: Use synonyms or related terminology.
4. **Explore related areas**: Look for adjacent teamspaces or similar topics.

---

## Search Quality

### Effective Search Queries
**Good queries** (specific and clear):
- "Kerberos TGS ticket behavior"
- "WMI abuse in Windows event logs"
- "PowerShell-based Kerberos abuse techniques"

**Weak queries** (too vague):
- "Kerberos"
- "WMI"
- "PowerShell abuse"

**Over-specific queries** (too narrow):
- "Kerberos TGS ticket request behavior for Windows 10 in AD 2025"

### User Context
Always tailor the query to the available user context:
- Use the terminology specific to the research topic.
- Focus on relevant teamspaces or domains.
- Refer to recent pages or team-specific content.

---

## Conclusion

Following these **Tavily Search Best Practices** ensures that you can perform targeted, efficient research for both system internals and adversary tradecraft. Use a **broad → narrow** search approach, apply filters strategically, and continuously refine your queries to focus on the most relevant and actionable results. With the correct usage of **Tavily Search**, you'll gather the right context to enhance your threat hunting workflows and investigations.