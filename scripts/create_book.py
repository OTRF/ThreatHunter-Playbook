import nbformat as nbf
import glob
import yaml
from os import path
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
        "analytic" : []
    },
    {
        "platform" : "Linux",
        "analytic" : []
    },
    {
        "platform" : "Mac",
        "analytic" : []
    },
    {
        "platform" : "AWS",
        "analytic" : []
    }
]

# ******* Initial TOC Template ********
with open('templates/toc_template.json') as json_file:
    toc_template = json.load(json_file)

# ******** Open every analytic yaml file available ****************
print("[+] Opening analytic yaml files..")
analytics_files = glob.glob(path.join(path.dirname(__file__), "..", "playbooks", "*.yaml"))
analytics_loaded = [yaml.safe_load(open(analytic_file).read()) for analytic_file in analytics_files]

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
    if analytic['playbook_link']:
        analytic_playbook_link = analytic['playbook_link']
    else:
        analytic_playbook_link = ''
    nb['cells'].append(nbf.v4.new_markdown_cell(
        """
|               |    |
|:--------------|:---|
| id            | {} |
| author        | {} |
| creation date | {} |
| platform      | {} |
| playbook link | {} |
        """.format(analytic['id'], analytic['author'], analytic['creation_date'], analytic['platform'], analytic_playbook_link)
    ))
    # *** TECHNICAL DESCRIPTION ****
    nb['cells'].append(nbf.v4.new_markdown_cell("""## Technical Description
{}""".format(analytic['description'])))
    # *** HYPOTHESIS ****
    nb['cells'].append(nbf.v4.new_markdown_cell("""## Hypothesis
{}""".format(analytic['hypothesis'])))
    # *** ANALYTICS ****
    nb['cells'].append(nbf.v4.new_markdown_cell("## Analytics"))
    nb['cells'].append(nbf.v4.new_markdown_cell("### Initialize Analytics Engine"))
    nb['cells'].append(nbf.v4.new_code_cell(
        """from openhunt.mordorutils import *
spark = get_spark()"""
    ))
    nb['cells'].append(nbf.v4.new_markdown_cell("### Download & Process Mordor File"))
    nb['cells'].append(nbf.v4.new_code_cell(
        """mordor_file = "{}"
registerMordorSQLTable(spark, mordor_file, "mordorTable")""".format(analytic['validation_dataset'][0]['url'])
    ))
    for a in analytic['analytics']:
        nb['cells'].append(nbf.v4.new_markdown_cell("### {}".format(a['name'])))
        nb['cells'].append(nbf.v4.new_markdown_cell(
            """
| FP Rate  | Log Channel | Description   |
| :--------| :-----------| :-------------|
| {}       | {}          | {}            |
            """.format(a['false_positives'], a['data_sources'], a['description'])
        ))
        nb['cells'].append(nbf.v4.new_code_cell(
            """df = spark.sql(
    '''
{}
    '''
)
df.show(10,False)""".format(a['logic'])
        ))
    # *** DETECTION BLINDSPOTS ****
    if analytic['detection_blindspots']:
        detection_blindspots = analytic['detection_blindspots']
    else:
        detection_blindspots = ''
    nb['cells'].append(nbf.v4.new_markdown_cell("""## Detection Blindspots
{}""".format(detection_blindspots)))
    # *** HUNTER NOTES ****
    if analytic['hunter_notes']:
        hunter_notes = analytic['hunter_notes']
    else:
        hunter_notes = ''
    nb['cells'].append(nbf.v4.new_markdown_cell("""## Hunter Notes
{}""".format(hunter_notes)))
    # *** HUNT OUTPUT****
    if analytic['hunt_output']:
        output_table = """
| Category | Type | Name     |
| :--------| :----| :--------|"""
        for output in analytic['hunt_output']:
            output_table += """
| {} | {} | [{}]({}) |""".format(output['category'], output['type'], output['name'], output['url'])   
    else:
        output_table = ''
    nb['cells'].append(nbf.v4.new_markdown_cell("""## Hunt Output
{}""".format(output_table)))
    # *** REFERENCES ****
    if analytic['references']:
        references = analytic['references']
    else:
        references = ''
    nb['cells'].append(nbf.v4.new_markdown_cell("""## References
{}""".format(references)))
    
    platform = analytic['platform'].lower()
    # ***** Update Summary Tables *******
    for table in summary_table:
        if platform in table['platform'].lower():
            for attack in analytic['attack_coverage']:
                for tactic in attack['tactics']:
                    analytic['location'] = attack_paths[tactic]
                    if analytic not in table['analytic']:
                        table['analytic'].append(analytic)

    # ***** Update main TOC template and creating notebook *****
    for attack in analytic['attack_coverage']:
        for toc in toc_template:
            if 'chapters' in toc.keys():
                for chapter in toc['chapters']:
                    if "notebooks/{}/{}".format(platform,platform) in chapter.values():
                        for section in chapter['sections']:
                            for tactic in attack['tactics']:
                                if attack_paths[tactic] in section['file']:
                                    analyticDict = {
                                        "file" : "notebooks/{}/{}/{}".format(platform,attack_paths[tactic], analytic['id'])
                                    }
                                    if analyticDict not in chapter['sections']:
                                        print("    [>>] Adding {} to {} path..".format(analytic['id'], attack_paths[tactic]))
                                        section['sections'].append(analyticDict)
                                        print("    [>>] Writing {} as a notebook to {}..".format(analytic['title'], attack_paths[tactic]))
                                        nbf.write(nb, "../docs/notebooks/{}/{}/{}.ipynb".format(platform,attack_paths[tactic],analytic['id']))

# ****** Removing empty lists ********
print("\n[+] Removing empty platforms and empty lists..")
for toc in toc_template[:]:
    if 'chapters' in toc.keys():
        for chapter in toc['chapters']:
            if 'sections' in chapter.keys() and len(chapter['sections']) > 0:
                for section in chapter['sections'][:]:
                    if 'sections' in section and not section['sections']:
                        print("  [>>] Removing {} ..".format(section['file']))
                        chapter['sections'].remove(section)

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
            for coverage in analytic['attack_coverage']:
                technique = coverage['technique']
                if technique not in techniques_mappings:
                    techniques_mappings[technique] = []
                    techniques_mappings[technique].append(metadata)
                elif technique in techniques_mappings:
                    if metadata not in techniques_mappings[technique]:
                        techniques_mappings[technique].append(metadata)
        
        VERSION = "3.0"
        NAME = "THP {} Analytics".format(summary['platform'])
        DESCRIPTION = "Analytics covered by the Threat Hunter Playbook {} detection notebooks".format(summary['platform'])
        DOMAIN = "mitre-enterprise"
        PLATFORM = summary['platform'].lower()

        print("  [>>] Creating navigator layer for {} analytics..".format(summary['platform']))
        thp_layer = {
            "description": DESCRIPTION,
            "name": NAME,
            "domain": DOMAIN,
            "version": VERSION,
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
        open('../docs/notebooks/{}/{}.md'.format(summary['platform'].lower(),summary['platform'].lower()), 'w').write(markdown)

# ******* Update Jupyter Book TOC File *************
print("\n[+] Writing final TOC file for Jupyter book..")
with open(r'../docs/_toc.yml', 'w') as file:
    yaml.dump(toc_template, file, sort_keys=False)