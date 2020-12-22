# {{summary['platform']}}
{% if summary['analytic']|length > 0 %}
## ATT&CK Navigator View

<iframe src="https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FOTRF%2FThreatHunter-Playbook%2Fmaster%2Fdocs%2Fnotebooks%2F{{summary['platform']|lower}}%2F{{summary['platform']|lower}}.json&tabs=false&selecting_techniques=false" width="950" height="450"></iframe>

## Table View

|Created|Analytic|Hypothesis|Author|
| :---| :---| :---| :---|
{% for s in summary['analytic']|sort(attribute='creation_date',reverse = True) %}|{{s['creation_date']}} |[{{s['title']}}](https://threathunterplaybook.com/notebooks/windows/{{s['location']}}/{{s['id']}}.html) |{{s['hypothesis']}} |{% for collaborator in s['collaborators'] %}{% set handle = collaborator.split('@') %} [{{collaborator}}](http://twitter.com/{{handle[1]}}){% if not loop.last %}, {% endif %}{% endfor %}  |
{% endfor %}{% endif %}
