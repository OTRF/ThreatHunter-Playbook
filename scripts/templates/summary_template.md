# {{summary['platform']}}

|Created|Analytic|Hypothesis|Author|
| :---| :---| :---| :---|
{% for s in summary['analytic']|sort(attribute='title') %}|{{s['creation_date']}} |[{{s['title']}}](https://threathunterplaybook.com/notebooks/windows/{{s['location']}}/{{s['id']}}.html) |{{s['hypothesis']}} |{{s['author']}} |
{% endfor %}