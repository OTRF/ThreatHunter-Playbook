# Free Telemetry Report

| Step | Procedure | Criteria | Technique | Detections |
| :---| :---| :---| :---| :---|
{% for s in renderyaml %}| {{s['step']}}|{{s['procedure']}}|{{s['criteria']}} | [{{s['technique']['name']}}](https://attack.mitre.org/techniques/{{s['technique']['id']}}) |<table><thead><tr><th>Type</th><th>Notes</th></tr></thead><tbody>{% for d in s['detections'] %}<tr><td>{{d['main_type']}}{% if d['modifier_type'] %}({{d['modifier_type']}}){% endif %}</td><td>{{d['description']}}{% if d['queries'] %}{% set count = namespace(value=1) %}{% for q in d['queries'] %} [[{{count.value}}](https://threathunterplaybook.com/evals/apt29/detections/{{s['step']}}_{{q['id']}}.html)]{% set count.value = count.value + 1 %}{% endfor %}{% endif %}</td></tr>{% endfor %}</tbody></table>|
{% endfor %}
