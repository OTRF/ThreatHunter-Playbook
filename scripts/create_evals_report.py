from jinja2 import Template
import copy
import yaml
import json
import glob
from os import path
import nbformat as nbf

print("[+] Processing files inside {} directory".format('../docs/evals/apt29/steps'))
# ******** Open every forge yaml file available ****************
print("[+] Opening report yaml files..")
yaml_files = sorted(glob.glob(path.join(path.dirname(__file__), '../docs/evals/apt29/steps', "*.yaml")), key=lambda x: (int(path.basename(x).split(".")[0]), str(path.basename(x).split(".")[1]), int(path.basename(x).split(".")[2].split("_")[0])))
yaml_loaded = [yaml.safe_load(open(yf).read()) for yf in yaml_files]

# ******** Steps Mapping ********
steps_list = [
    "Step Zero",
    "Initial Compromise",
    "Collection",
    "Deploy Stealth Toolkit",
    "Clean Up",
    "Establish Persistence",
    "Credential Access",
    "Collection",
    "Expand Access",
    "Clean Up, Collection and Exfiltration",
    "Persistence Execution"
]

# ******** Create Logic -> Output Documents ********
otr_list = []
detection_template = Template(open("templates/evals_detection_template.md").read())
print("\n[+]Creating detection documents..")
for step in yaml_loaded:
    for detection in step['detections']:
        # ***** Get Report Stats *****
        otr_dict = {
            "vendor" : step['vendor'],
            "step" : step['step'].split(".")[0],
            "stepname": steps_list[int(step['step'].split(".")[0])],
            "substep" : step['step'],
            "techniqueid" : step['technique']['id'],
            "techniquename" : step['technique']['name'],
            "detectiontype" : detection['main_type'],
            "detectionotes" : detection['description']
        }
        otr_list.append(otr_dict)
        # ***** Create Detection Documents *****
        if detection['queries']:
            for q in detection['queries']:
                query_for_render = copy.deepcopy(q)
                markdown = detection_template.render(renderquery=query_for_render)
                if (path.exists('../docs/evals/apt29/detections/{}_{}.md'.format(step['step'],q['id']))):
                    print('[!] {}_{}.md already exists'.format(step['step'],q['id']))
                else:
                    print('  [>] {}_{}.md detection created'.format(step['step'],q['id']))
                    open('../docs/evals/apt29/detections/{}_{}.md'.format(step['step'],q['id']), 'w').write(markdown)

# ******** Create OTR Results JSON File ********
print("\n[+] Creating the APT29 OTR JSON File..")
with open('../docs/evals/apt29/data/otr_results.json', 'w') as results:
    json.dump(otr_list, results)

# ******** Creating APT29 Evals Notebook ********
print("\n[+] Creating the APT29 Evals Notebook..")
# **** METADATA ****
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
# **** INITIALIZE NOTEBOOK ****
nb = nbf.v4.new_notebook(metadata=metadata)
nb['cells'] = []
# *** TITLE ****
nb['cells'].append(nbf.v4.new_markdown_cell("# Free Telemetry Notebook"))
# *** METADATA ****
nb['cells'].append(nbf.v4.new_markdown_cell(
    """
|               |    |
|:--------------|:---|
| Group         | APT29 |
| Description   | APT29 is a threat group that has been attributed to the Russian government and has operated since at least 2008. This group reportedly compromised the Democratic National Committee starting in the summer of 2015 |
| Author        | [Open Threat Research - APT29 Detection Hackathon](https://github.com/OTRF/detection-hackathon-apt29) |
    """
))
# **** SETUP ****
# **** IMPORT LIBRARIES ****
nb['cells'].append(nbf.v4.new_markdown_cell("### Import Libraries"))
nb['cells'].append(nbf.v4.new_code_cell("from pyspark.sql import SparkSession"))

# **** START SPARK SPESSION ****
nb['cells'].append(nbf.v4.new_markdown_cell("### Start Spark Session"))
nb['cells'].append(nbf.v4.new_code_cell(
    """spark = SparkSession.builder.getOrCreate()
spark.conf.set("spark.sql.caseSensitive", "true")"""
))

# **** DECOMPRESS HOST DATASETS ****
nb['cells'].append(nbf.v4.new_markdown_cell("### Decompress Dataset"))
nb['cells'].append(nbf.v4.new_code_cell("!wget https://github.com/hunters-forge/mordor/raw/master/datasets/large/apt29/day1/apt29_evals_day1_manual.zip"))
nb['cells'].append(nbf.v4.new_code_cell("!unzip apt29_evals_day1_manual.zip"))

# **** IMPORT HOST DATASETS ****
nb['cells'].append(nbf.v4.new_markdown_cell("### Import Datasets"))
nb['cells'].append(nbf.v4.new_code_cell("df_day1_host = spark.read.json('apt29_evals_day1_manual_2020-05-01225525.json')"))

# **** CREATE TEMPORARY SQL VIEW ****
nb['cells'].append(nbf.v4.new_markdown_cell("### Create Temporary SQL View"))
nb['cells'].append(nbf.v4.new_code_cell("df_day1_host.createTempView('apt29Host')"))

# **** ADVERSARY - DETECTION STEPS ****
nb['cells'].append(nbf.v4.new_markdown_cell("## Adversary - Detection Steps"))
for yaml in yaml_loaded:
    print("  [>] Processing Step {}..".format(yaml['step']))
    # **** MAIN STEPS ****
    nb['cells'].append(nbf.v4.new_markdown_cell("""## {}. {}
**Procedure:** {}
\n**Criteria:** {}
""".format(yaml['step'],yaml['technique']['name'],yaml['procedure'],yaml['criteria'])))
    # **** DETECTIONS ****
    for detection in yaml['detections']:
        nb['cells'].append(nbf.v4.new_markdown_cell("### Detection Type:{}({})".format(detection['main_type'],detection['modifier_type'])))
        if detection['queries']:
            # **** AVAILABLE QUERIES ****
            for q in detection['queries']:
                nb['cells'].append(nbf.v4.new_markdown_cell("**Query ID:{}**".format(q['id'])))
                nb['cells'].append(nbf.v4.new_code_cell("""df = spark.sql(
'''
{}
'''
)
df.show(100,truncate = False, vertical = True)""".format(q['logic'])))

# **** Writing APT29 Evals Notebook *****
print("\n  [>] Writing notebook to ../docs/notebooks/campaigns/apt29Evals.ipynb")
nbf.write(nb, "../docs/notebooks/campaigns/apt29Evals.ipynb")

# ******** Creating APT29 Evals Markdown Report ********
print("\n[+] Creating APT29 Evals Markdown Report..")
# ******** Open forge template ****************
print("  [>] Reading report template..")
yaml_template = Template(open("templates/evals_report_template.md").read())

# Create Markdown file
print("  [>] Writing steps to markdown ..")
yaml_for_render = copy.deepcopy(yaml_loaded)

# Generate the markdown
markdown = yaml_template.render(renderyaml=yaml_for_render)
print("\n  [>] Writing Markdown report to ../docs/evals/apt29/report.md")
open('../docs/evals/apt29/report.md', 'w').write(markdown)