import glob
import yaml
import os
import json
import csv
from jinja2 import Template

###### Variables #####
current_directory = os.path.dirname(__file__)
docs_directory = os.path.join(current_directory, "../../", "docs")
library_directory = os.path.join(docs_directory, "library")
hunts_directory = os.path.join(docs_directory, "hunts")
toc_template = os.path.join(current_directory, 'templates/toc_template.json')
toc_file = os.path.join(docs_directory, "_toc.yml")
summary_template_file = os.path.join(current_directory, 'templates/summary_template.md')

###### ATT&CK Tactics Mappings #######
attack_paths = {
    "TA0001" : "Initial Access",
    "TA0002" : "Execution",
    "TA0003" : "Persistence",
    "TA0004" : "Privilege Escalation",
    "TA0005" : "Defense Evasion",
    "TA0006" : "Credential Access",
    "TA0007" : "Discovery",
    "TA0008" : "Lateral Movement",
    "TA0009" : "Collection",
    "TA0011" : "Command and Control",
    "TA0010" : "Exfiltration",
    "TA0040" : "Impact"
}

###### Analytic Summary ########
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

###### Initial TOC Template #######
with open(toc_template) as json_file:
    toc_template = json.load(json_file)

# ******** Open every analytic yaml file available ****************
print("[+] Opening analytic yaml files..")
hunt_files = glob.glob(os.path.join(hunts_directory, "/**/", "metadata.yaml"), recursive = True)
#hunts_loaded = []
#for hunt_file in hunt_files:
#    hunts_loaded.append(yaml.safe_load(open(hunt_file).read()))
hunts_loaded = [yaml.safe_load(open(hunt_file).read()) for hunt_file in hunt_files]

# ******** Translating YAML files to Notebooks ****************
print("\n[+] Processing metadata yaml files..")
for analytic in hunts_loaded:
    print(analytic['id'])
    platform = analytic['platform'].lower()
    # ***** Update Summary Tables *******
    for table in summary_table:
        if platform in table['platform'].lower():
            for attack in analytic['attack_mappings']:
                if analytic not in table['analytic']:
                    table['analytic'].append(analytic)

###### Updating Detections TOC File ######
print("\n[+] Creating detection entries in TOC file..")
for toc in toc_template['parts']:
    if 'caption' in toc.keys():
        if toc['caption'] == 'Guided Hunts':
            for table in summary_table:
                table_platform = table['platform'].lower()
                if len(table['analytic']) > 0:
                    analytic_platform = {
                        "file": "hunts/{}/intro".format(table_platform),
                        "sections": [
                            {
                                "file": "hunts/{}/{}/notebook".format(table_platform,analytic['id']),
                            } for analytic in table['analytic']
                        ]
                    }
                    toc['chapters'].append(analytic_platform)

###### Update Knowledge Library Content ######
print("\n[+] Creating Knowledge Library entries in TOC file..")
for toc in toc_template['parts']:
    if 'caption' in toc.keys():
        if toc['caption'] == 'Knowledge Library':
            subfolders = [ f.name for f in os.scandir("{}/".format(library_directory)) if f.is_dir() ]
            for category in subfolders:
                if len(os.listdir("{}/{}/".format(library_directory,category))) > 1:
                    librarydocs = {
                        "file" : "library/{}/intro".format(category),
                        "sections": [
                            {
                                "file": "library/{}/{}".format(category,filename.split('.md')[0])
                            } for filename in os.listdir("{}/{}/".format(library_directory,category)) if filename != 'intro.md'
                        ]
                    }
                    toc['chapters'].append(librarydocs)

###### Creating Analytics Summaries ######
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
        
        LAYER_VERSION = "4.3"
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
        open('{}/{}/attack_navigator.json'.format(hunts_directory,PLATFORM), 'w').write(json.dumps(thp_layer))
    
print("\n[+] Creating analytic summary tables for each platform..")
summary_template = Template(open(summary_template_file).read())
for summary in summary_table:
    if len(summary['analytic']) > 0:
        print("  [>>] Creating markdown for {} analytics..".format(summary['platform']))
        markdown = summary_template.render(platform=summary['platform'],analytic_count=len(summary['analytic']))
        open('{}/{}/intro.md'.format(hunts_directory,summary['platform'].lower()), 'w').write(markdown)

        print("  [>>] Creating csv file for {} analytics..".format(summary['platform']))
        myCsvFile = open('{}/{}/analytic_summary.csv'.format(hunts_directory,summary['platform'].lower()), 'w', newline='')
        writer = csv.writer(myCsvFile)
        writer.writerow(['Creation Date','Id','Title','Tactics','Collaborators'])
        for analytic in summary['analytic']:
            analytic_dict = dict()
            analytic_dict['creation_date'] = analytic['creation_date']
            analytic_dict['id'] = analytic['id']
            analytic_dict['title'] = analytic['title']
            if 'attack_mappings' in analytic.keys():
                tactics = []
                for am in analytic['attack_mappings']:
                    for t in am['tactics']:
                        tactics.append(attack_paths[t])
                analytic_dict['tactics'] = tactics
            else:
                analytic_dict['tactics'] = []
            analytic_dict['collaborators'] = analytic['collaborators']
            writer.writerow(analytic_dict.values())
        myCsvFile.close()

###### Update Jupyter Book TOC File ######
print("\n[+] Writing final TOC file for Jupyter book..")
with open(toc_file, 'w') as file:
    yaml.dump(toc_template, file, sort_keys=False)