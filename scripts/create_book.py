import nbformat as nbf
import glob
import yaml
import os
import json
import copy
from jinja2 import Template

# ******* Paths for notebooks ********
attack_paths = {
    "TA0001" : "01_initial_access",
    "TA0002" : "02_execution",
    "TA0003" : "03_persistence",
    "TA0004" : "04_privilege_escalation",
    "TA0005" : "05_defense_evasion",
    "TA0006" : "06_credential_access",
    "TA0007" : "07_discovery",
    "TA0008" : "08_lateral_movement",
    "TA0009" : "09_collection",
    "TA0011" : "11_command_and_control",
    "TA0010" : "10_exfiltration",
    "TA0040" : "12_impact/impact"
}

# ******* Analytic Summary *********
summary_table = [
    {
        "platform" : "Windows",
        "analytic" : [],
        "tactics" : []
    },
    {
        "platform" : "Linux",
        "analytic" : [],
        "tactics" : []
    },
    {
        "platform" : "Mac",
        "analytic" : [],
        "tactics" : []
    },
    {
        "platform" : "AWS",
        "analytic" : [],
        "tactics" : []
    }
]

# ******* Initial TOC Template ********
with open('templates/toc_template.json') as json_file:
    toc_template = json.load(json_file)

# ******** Open every analytic yaml file available ****************
print("[+] Opening analytic yaml files..")
analytics_files = glob.glob(os.path.join(os.path.dirname(__file__), "..", "playbooks", "*.yaml"))
analytics_loaded = []
for analytic_file in analytics_files:
    print(analytic_file)
    analytics_loaded.append(yaml.safe_load(open(analytic_file).read()))
#analytics_loaded = [yaml.safe_load(open(analytic_file).read()) for analytic_file in analytics_files]

# ******** Translating YAML files to Notebooks ****************
print("\n[+] Translating YAML files to notebooks..")
for analytic in analytics_loaded:
    print("  [>>] Processing {} file..".format(analytic['title']))
    # METADATA
    metadata = {
        "kernelspec": {
            "display_name": "PySpark_Python3",
            "language": "python",
            "name": "pyspark3"
        },
        "language_info": {
            "codemirror_mode": {
                "name": "ipython",
                "version": 3
            },
            "file_extension": ".py",
            "mimetype": "text/x-python",
            "name": "python",
            "nbconvert_exporter": "python",
            "pygments_lexer": "ipython3",
            "version": "3.7.3"
        }
    } 
    nb = nbf.v4.new_notebook(metadata=metadata)
    nb['cells'] = []
    # *** TITLE ****
    nb['cells'].append(nbf.v4.new_markdown_cell("# {}".format(analytic['title'])))
    # *** METADATA ****
    nb['cells'].append(nbf.v4.new_markdown_cell("## Metadata"))
    playbooks_related = []
    if analytic['playbooks_related']:
        playbooks_related= [p for p in analytic['playbooks_related']]
    collaborators = [c for c in analytic['collaborators']]
    nb['cells'].append(nbf.v4.new_markdown_cell("""
|     Metadata      |  Value  |
|:------------------|:---|
| collaborators     | {} |
| creation date     | {} |
| modification date | {} |
| playbook related  | {} |""".format(collaborators, analytic['creation_date'], analytic['modification_date'], playbooks_related)
    ))
    # *** HYPOTHESIS ****
    nb['cells'].append(nbf.v4.new_markdown_cell("""## Hypothesis
{}""".format(analytic['hypothesis'])))
    # *** TECHNICAL CONTEXT ****
    nb['cells'].append(nbf.v4.new_markdown_cell("""## Technical Context
{}""".format(analytic['technical_context'])))
    # *** OFFENSIVE TRADECRAFT ****
    nb['cells'].append(nbf.v4.new_markdown_cell("""## Offensive Tradecraft
{}""".format(analytic['offensive_tradecraft'])))
    # *** TEST DATA ***
    nb['cells'].append(nbf.v4.new_markdown_cell("## Security Datasets"))
    nb['cells'].append(nbf.v4.new_markdown_cell("""
| Metadata  |    Value  |
|:----------|:----------|
| docs      | {}        |
| link      | [{}]({})  |""".format(analytic['test_data']['metadata'], analytic['test_data']['link'],analytic['test_data']['link'])
    ))
    # *** ANALYTICS ****
    nb['cells'].append(nbf.v4.new_markdown_cell("## Analytics"))
    nb['cells'].append(nbf.v4.new_markdown_cell("### Initialize Analytics Engine"))
    nb['cells'].append(nbf.v4.new_code_cell(
        """from openhunt.mordorutils import *
spark = get_spark()"""
    ))
    nb['cells'].append(nbf.v4.new_markdown_cell("### Download & Process Security Dataset"))
    nb['cells'].append(nbf.v4.new_code_cell(
        """sd_file = "{}"
registerSDSQLTable(spark, sd_file, "sdTable")""".format(analytic['test_data']['link'])
    ))
    ## *** PROCESSING EACH ANALYTIC ***
    for a in analytic['analytics']:
        nb['cells'].append(nbf.v4.new_markdown_cell("""### {}
{}""".format(a['name'],a['description'])))
        #### *** DATA MODEL ***
        table = """
| Data source | Event Provider | Relationship | Event |
|:------------|:---------------|--------------|-------|"""
        table_list = [table]
        for d in a['data_sources']:
            for e in d['event_providers']:
                for dm in e['data_model']:
                    table_list.append("| {} | {} | {} | {} |".format(d['name'],e['name'],dm['relationship'],dm['event_id']))
        table_strings = '\n'.join(map(str, table_list))
        nb['cells'].append(nbf.v4.new_markdown_cell(table_strings))
        ### *** ANALYTIC QUERY - LOGIC
        nb['cells'].append(nbf.v4.new_code_cell(
            """df = spark.sql(
'''
{}
'''
)
df.show(10,False)""".format(a['logic'])
        ))
    # *** KNOWN BYPASSES ****
    nb['cells'].append(nbf.v4.new_markdown_cell("## Known Bypasses"))
    table = """
| Idea | Playbook |
|:-----|:---------|"""
    table_list = [table]
    if analytic['known_bypasses']:
        for b in analytic['known_bypasses']:
            playbook_link = "https://github.com/OTRF/ThreatHunter-Playbook/blob/master/playbooks/{}.yaml".format(b['playbook'])
            table_list.append("| {} | [{}]({}) |".format(b['idea'],b['playbook'],playbook_link))
        table_strings = '\n'.join(map(str, table_list))
        nb['cells'].append(nbf.v4.new_markdown_cell(table_strings))
    # *** FALSE POSITIVES ****
    nb['cells'].append(nbf.v4.new_markdown_cell("""## False Positives
{}""".format(analytic['false_positives'])))
    # *** HUNTER NOTES ****
    nb['cells'].append(nbf.v4.new_markdown_cell("""## Hunter Notes
{}""".format(analytic['additional_notes'])))
    # *** HUNT OUTPUT****
    output_table = """
| Type | Link |
| :----| :----|"""
    if analytic['research_output']:
        for output in analytic['research_output']:
            output_table += """
| {} | [{}]({}) |""".format(output['type'],output['link'],output['link'])   
        nb['cells'].append(nbf.v4.new_markdown_cell("""## Hunt Output
{}""".format(output_table)))
    # *** REFERENCES ****
    references = ''
    if analytic['references']:
        references = analytic['references']
        nb['cells'].append(nbf.v4.new_markdown_cell("""## References
{}""".format(references)))
    
    platform = analytic['platform'].lower()
    # ***** Update Summary Tables *******
    for table in summary_table:
        if platform in table['platform'].lower():
            for attack in analytic['attack_mappings']:
                for tactic in attack['tactics']:
                    analytic['location'] = attack_paths[tactic]
                    if analytic not in table['analytic']:
                        table['analytic'].append(analytic)
                    if attack_paths[tactic] not in table['tactics']:
                        table['tactics'].append(attack_paths[tactic])

    # ***** Create Notebooks *****
    for attack in analytic['attack_mappings']:
        for tactic in attack['tactics']:
            nbf.write(nb, "../docs/notebooks/{}/{}/{}.ipynb".format(platform,attack_paths[tactic],analytic['id']))

# ****** Updating Detections TOC File ********
print("\n[+] Creating detection entries in TOC file..")
for toc in toc_template['parts']:
    if 'caption' in toc.keys():
        if toc['caption'] == 'Targeted Notebooks':
            for table in summary_table:
                table_platform = table['platform'].lower()
                if len(table['analytic']) > 0:
                    analytic_platform = {
                        "file": "notebooks/{}/intro".format(table_platform),
                        "sections": [
                            {
                                "file": "notebooks/{}/{}/intro".format(table_platform,tactic),
                                "sections": [
                                    {
                                        "file": "notebooks/{}/{}/{}".format(table_platform,tactic,analytic['id'])
                                    } for analytic in table['analytic'] for maps in analytic['attack_mappings'] for t in maps['tactics'] if attack_paths[t] == tactic
                                ]
                            } for tactic in sorted(table['tactics'])
                        ]
                    }
                    toc['chapters'].append(analytic_platform)

# ***** Update Knowledge Library Content *****
print("\n[+] Creating Knowledge Library entries in TOC file..")
for toc in toc_template['parts']:
    if 'caption' in toc.keys():
        if toc['caption'] == 'Knowledge Library':
            subfolders = [ f.name for f in os.scandir("../docs/library/") if f.is_dir() ]
            for category in subfolders:
                if len(os.listdir("../docs/library/{}/".format(category))) > 1:
                    librarydocs = {
                        "file" : "library/{}/intro".format(category),
                        "sections": [
                            {
                                "file": "library/{}/{}".format(category,filename.split('.md')[0])
                            } for filename in os.listdir("../docs/library/{}/".format(category)) if filename != 'intro.md'
                        ]
                    }
                    toc['chapters'].append(librarydocs)

# ****** Creating Analytics Summaries ******
print("\n[+] Creating ATT&CK navigator layers for each platform..")
# Reference: https://github.com/mitre-attack/car/blob/master/scripts/generate_attack_nav_layer.py#L30-L45
for summary in summary_table:
    if len(summary['analytic']) > 0:
        techniques_mappings = dict()
        for analytic in summary['analytic']:
            metadata = dict()
            metadata['name'] = analytic['title']
            metadata['value'] = analytic['id'] 
            for coverage in analytic['attack_mappings']:
                technique = coverage['technique']
                if technique not in techniques_mappings:
                    techniques_mappings[technique] = []
                    techniques_mappings[technique].append(metadata)
                elif technique in techniques_mappings:
                    if metadata not in techniques_mappings[technique]:
                        techniques_mappings[technique].append(metadata)
        
        LAYER_VERSION = "4.2"
        NAVIGATOR_VERSION = "4.5.5"
        NAME = "THP {} Analytics".format(summary['platform'])
        DESCRIPTION = "Analytics covered by the Threat Hunter Playbook {} detection notebooks".format(summary['platform'])
        DOMAIN = "mitre-enterprise"
        PLATFORM = summary['platform'].lower()

        print("  [>>] Creating navigator layer for {} analytics..".format(summary['platform']))
        thp_layer = {
            "description": DESCRIPTION,
            "name": NAME,
            "domain": DOMAIN,
            "versions": {
                "attack": "10",
                "navigator": NAVIGATOR_VERSION,
                "layer": LAYER_VERSION
            },
            "techniques": [
                {
                    "score": 1,
                    "techniqueID" : k,
                    "metadata": v
                } for k,v in techniques_mappings.items()
            ],
            "gradient": {
                "colors": [
                    "#ffffff",
                    "#66fff3"
                ],
                "minValue": 0,
                "maxValue": 1
            },
            "legendItems": [
                {
                    "label": "Techniques researched",
                    "color": "#66fff3"
                }
            ]
        }
        open('../docs/notebooks/{}/{}.json'.format(PLATFORM,PLATFORM), 'w').write(json.dumps(thp_layer))
    
print("\n[+] Creating analytic summary tables for each platform..")
summary_template = Template(open('templates/summary_template.md').read())
for summary in summary_table:
    if len(summary['analytic']) > 0:
        print("  [>>] Creating summary table for {} analytics..".format(summary['platform']))
        summary_for_render = copy.deepcopy(summary)
        markdown = summary_template.render(summary=summary_for_render)
        open('../docs/notebooks/{}/intro.md'.format(summary['platform'].lower()), 'w').write(markdown)

# ******* Update Jupyter Book TOC File *************
print("\n[+] Writing final TOC file for Jupyter book..")
with open(r'../docs/_toc.yml', 'w') as file:
    yaml.dump(toc_template, file, sort_keys=False)
