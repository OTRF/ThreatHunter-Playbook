---
jupytext:
  formats: md:myst
  text_representation:
    extension: .md
    format_name: myst
    format_version: '1.3'
    jupytext_version: 1.14.1
kernelspec:
  display_name: Python 3
  language: python
  name: python3
---

# Windows

## ATT&CK Navigator View

<iframe src="https://mitre-attack.github.io/attack-navigator/enterprise/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FOTRF%2FThreatHunter-Playbook%2Fmaster%2Fdocs%2Fhunts%2Fwindows%2Fattack_navigator.json&tabs=false&selecting_techniques=false" width="950" height="450"></iframe>

## Interactive Table: 26 Hunts

```{code-cell} Ipython3
:tags: ['remove-input']

import pandas as pd
import itables.options as opt
from itables import init_notebook_mode

opt.classes = ["display", "cell-border"]
init_notebook_mode(all_interactive=True)

def make_clickable(id,name):
    return f'<a href="https://threathunterplaybook.com/hunts/windows/{id}/notebook.html">{name}</a>'

df = pd.read_csv('analytic_summary.csv')
df['Title'] = df.apply(lambda x: make_clickable(x['Id'], x['Title']), axis=1)
df.drop('Id', axis=1, inplace=True)
df
```
