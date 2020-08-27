# {{group['group_id']}}:{{group['name']}}

## Description

{{group['description']}}

## TTPs

|Platform|Tactic|Technique|Description|Data Sources|
|---|---|---|---|---|
{% for t in group['techniques'] %}|{% if 'platform' in t %}{% for platform in t['platform'] %}{{platform}}{% if not loop.last %}, {% endif %}{% endfor %}{% endif %}|{% for tactic in t['tactics'] %}[{{tactic}}](https://attack.mitre.org/tactics/{{tactic}}/){% if not loop.last %}, {% endif %}{% endfor %} |[{{t['techniqueName']}}](https://attack.mitre.org/techniques/{{t['techniqueId']}}/) |{{t['relationshipComment']}} |{% if 'dataSources' in t %}{% for dataSource in t['dataSources'] %}{{dataSource}}{% if not loop.last %}, {% endif %}{% endfor %}{% endif %}|
{% endfor %}
