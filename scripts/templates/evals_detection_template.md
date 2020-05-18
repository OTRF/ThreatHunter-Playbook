# {{renderquery['id']}}

## Data Sources
{% for d in renderquery['data_sources'] %}* {{d}}<br>{% endfor %}

## Logic

```
{{renderquery['logic']}}
```

## Output

```
{{renderquery['output']}}
```