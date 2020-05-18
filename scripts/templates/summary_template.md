# {{summary['platform']}}
{% if summary['analytic']|length > 0 %}
## ATT&CK Navigator View

<iframe src="https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2Fhunters-forge%2FThreatHunter-Playbook%2Fmaster%2Fdocs%2Fnotebooks%2F{{summary['platform']|lower}}%2F{{summary['platform']|lower}}.json&tabs=false&selecting_techniques=false" width="950" height="450"></iframe>

## Table View

|Created|Analytic|Hypothesis|Author|
| :---| :---| :---| :---|
{% for s in summary['analytic']|sort(attribute='title') %}|{{s['creation_date']}} |[{{s['title']}}](https://threathunterplaybook.com/notebooks/windows/{{s['location']}}/{{s['id']}}.html) |{{s['hypothesis']}} |{{s['author']}} |
{% endfor %}{% endif %}