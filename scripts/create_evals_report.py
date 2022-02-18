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
    "0:Step Zero",
    "1:Initial Compromise",
    "2:Collection & Exfiltration",
    "3:Deploy Stealth Toolkit",
    "4:Clean Up",
    "5:Establish Persistence",
    "6:Credential Access",
    "7:Collection & Exfiltration",
    "8:Expand Access",
    "9:Clean Up, Collection and Exfiltration",
    "10:Persistence Execution"
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

# **** REPORT BAR CHART ****
nb['cells'].append(nbf.v4.new_markdown_cell("## Telemetry Detection Category"))
nb['cells'].append(nbf.v4.new_code_cell(source='''# Importing Libraries
from bokeh.io import show
from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, LabelSet, HoverTool
from bokeh.transform import dodge
import pandas as pd

# You need to run this code at the beginning in order to show visualization using Jupyter Notebooks
from bokeh.io import output_notebook
output_notebook()
apt29= pd.read_json('https://raw.githubusercontent.com/OTRF/ThreatHunter-Playbook/master/docs/evals/apt29/data/otr_results.json')
summary = (
    apt29
    .groupby(['step','stepname']).agg(total=pd.NamedAgg(column="substep", aggfunc="nunique"))
    .join(
        apt29[apt29['detectiontype'] == 'Telemetry']
        .groupby(['step','stepname']).agg(telemetry=pd.NamedAgg(column="vendor", aggfunc="count"))
    )
).reset_index()
summary['percentage'] = (summary['telemetry'] / summary['total']).map("{:.0%}".format)
# Get Total Average Telemetry coverage
total_avg_percentage = '{0:.0f}'.format((summary['telemetry'].sum() / summary['total'].sum() * 100))

# Lists of values to create ColumnDataSource
stepname = summary['stepname'].tolist()
total = summary['total'].tolist()
telemetry = summary['telemetry'].tolist()
percentage = summary['percentage'].tolist()

# Creating ColumnDataSource object: source of data for visualization
source = ColumnDataSource(data={'stepname':stepname,'sub-Steps':total,'covered':telemetry,'percentage':percentage})

# Defining HoverTool object (Display info with Mouse): It is applied to chart named 'needHover'
hover_tool = HoverTool(names = ['needHover'],tooltips = [("Covered", "@covered"),("Percentage", "@percentage")])

# Creating Figure
p = figure(x_range=stepname,y_range=(0,23),plot_height=550,plot_width=600,toolbar_location='right',tools=[hover_tool])

# Creating Vertical Bar Charts
p.vbar(x=dodge('stepname',0.0,range=p.x_range),top='sub-Steps',width=0.7,source=source,color="#c9d9d3",legend_label="Total")
p.vbar(x=dodge('stepname',0.0, range=p.x_range),top='covered',width=0.7,source=source,color="#718dbf",legend_label="Covered", name = 'needHover')

# Adding Legend
p.legend.location = "top_right"
p.legend.orientation = "vertical"
p.legend.border_line_width = 3
p.legend.border_line_color = "black"
p.legend.border_line_alpha = 0.3

# Adding Title
p.title.text = 'Telemetry Detection Category (Average Coverage: {}%)'.format(total_avg_percentage)
p.title.align = 'center'
p.title.text_font_size = '12pt'

# Adding Axis Labels
p.xaxis.axis_label = 'Emulation Steps'
p.xaxis.major_label_orientation = 45

p.yaxis.axis_label = 'Count of Sub-Steps'

# Adding Data Label: Only for total of sub-steps
total_label = LabelSet(x='stepname',y='sub-Steps',text='sub-Steps',text_align='center',level='glyph',source= source)
p.add_layout(total_label)

#Showing visualization
show(p)
''', metadata={"tags":["hide-input"]}))

# **** SETUP ****
# **** IMPORT LIBRARIES ****
nb['cells'].append(nbf.v4.new_markdown_cell("## Import Libraries"))
nb['cells'].append(nbf.v4.new_code_cell("from pyspark.sql import SparkSession"))

# **** START SPARK SPESSION ****
nb['cells'].append(nbf.v4.new_markdown_cell("## Start Spark Session"))
nb['cells'].append(nbf.v4.new_code_cell(
    """spark = SparkSession.builder.getOrCreate()
spark.conf.set("spark.sql.caseSensitive", "true")"""
))

# **** DECOMPRESS HOST DATASETS ****
nb['cells'].append(nbf.v4.new_markdown_cell("## Decompress Dataset"))
nb['cells'].append(nbf.v4.new_code_cell("!wget https://github.com/OTRF/Security-Datasets/raw/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip"))
nb['cells'].append(nbf.v4.new_code_cell("!unzip apt29_evals_day1_manual.zip"))

# **** IMPORT HOST DATASETS ****
nb['cells'].append(nbf.v4.new_markdown_cell("## Import Datasets"))
nb['cells'].append(nbf.v4.new_code_cell("df_day1_host = spark.read.json('apt29_evals_day1_manual_2020-05-01225525.json')"))

# **** CREATE TEMPORARY SQL VIEW ****
nb['cells'].append(nbf.v4.new_markdown_cell("## Create Temporary SQL View"))
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
