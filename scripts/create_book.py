import nbformat as nbf
import glob
import yaml
from os import path
import json

# ******* Paths for notebooks ********
attack_paths = {
    "TA0001" : "01_initial_access/initial_access",
    "TA0002" : "02_execution/execution",
    "TA0003" : "03_persistence/persistence",
    "TA0004" : "04_privilege_escalation/privilege_escalation",
    "TA0005" : "05_defense_evasion/defense_evasion",
    "TA0006" : "06_credential_access/credential_access",
    "TA0007" : "07_discovery/discovery",
    "TA0008" : "08_lateral_movement/lateral_movement",
    "TA0009" : "09_collection/collection",
    "TA0011" : "11_command_and_control/command_and_control",
    "TA0010" : "10_exfiltration/exfiltration",
    "TA0040" : "12_impact/impact"
}
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
    nb = nbf.v4.new_notebook() 
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
df.show(1,False)""".format(a['logic'])
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
    
    # ***** Update main TOC template and creating notebook *****
    platform = analytic['platform'].lower()
    for attack in analytic['attack_coverage']:
        for to in toc_template:
            if "/notebooks/{}/{}".format(platform,platform) in to.values():
                for section in to['sections']:
                    for tactic in attack['tactics']:
                        if attack_paths[tactic] in section['url']:
                            analyticDict = {
                                "url" : "/notebooks/{}/{}/{}".format(platform,attack_paths[tactic], analytic['id']),
                                "not_numbered" : True
                            }
                            if analyticDict not in section['subsections']:
                                print("    [>>] Adding {} to {} path..".format(analytic['id'], attack_paths[tactic]))
                                section['subsections'].append(analyticDict)
                                print("    [>>] Writing {} as a notebook to {}..".format(analytic['title'], attack_paths[tactic]))
                                nbf.write(nb, "../docs/content/notebooks/{}/{}/{}.ipynb".format(platform,attack_paths[tactic],analytic['id']))

# ****** Removing empty lists ********
print("\n[+] Removing empty platforms and empty lists ..")
for to in toc_template[:]:
    if 'sections' in to.keys() and len(to['sections']) > 0:
        for section in to['sections'][:]:
            if 'subsections' in section and not section['subsections']:
                print("  [>>] Removing {} ..".format(section['url']))
                to['sections'].remove(section)

# ******* Update Jupyter Book TOC File *************
print("\n[+] Writing final TOC file for Jupyter book..")
with open(r'../docs/_data/toc.yml', 'w') as file:
    yaml.dump(toc_template, file, sort_keys=False)