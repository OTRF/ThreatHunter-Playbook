import json
import glob
import yaml
from os import path
import pandas as pd
import altair as alt

# Load Vendor Results JSOn
with open('../docs/evals/apt29/data/vendor_results.json','r') as fi:
    vendor_list = json.load(fi)

# ******** Steps Mapping ********
steps_list = [
    "Step Zero",
    "Initial Compromise",
    "Exfiltration",
    "Deploy Stealth Toolkit",
    "Clean Up",
    "Establish Persistence",
    "Credential Access",
    "(2) Collection and Exfiltration",
    "Expand Access",
    "Clean Up, Collection and Exfiltration",
    "Persistence Execution"
]

# Read all YAML Files from report
yaml_files = sorted(glob.glob(path.join(path.dirname(__file__), '../docs/evals/apt29/steps', "*.yaml")), key=lambda x: (int(path.basename(x).split(".")[0]), str(path.basename(x).split(".")[1]), int(path.basename(x).split(".")[2].split("_")[0])))
yaml_loaded = [yaml.safe_load(open(yf).read()) for yf in yaml_files]

for step in yaml_loaded:
    for detection in step['detections']:
        otrDict = {
            "vendor" : step['vendor'],
            "step" : step['step'].split(".")[0],
            "stepname": steps_list[int(step['step'].split(".")[0])],
            "substep" : step['step'],
            "techniqueid" : step['technique']['id'],
            "techniquename" : step['technique']['name'],
            "detectiontype" : detection['main_type'],
            "detectionotes" : detection['description']
        }
        vendor_list.append(otrDict)

# Results -> DataFrame
#apt29_df = pd.DataFrame(vendor_list)
apt29_df = pd.read_json('https://raw.githubusercontent.com/OTRF/ThreatHunter-Playbook/master/docs/evals/apt29/data/otr_results.json')
apt29_telemetry = (
    apt29_df[['vendor','step','substep','stepname','detectiontype']]
    [(apt29_df['detectiontype'] == 'Telemetry')]
)
apt29_grouped = (
    apt29_telemetry[['vendor','step','substep','stepname','detectiontype']]
    [(apt29_telemetry['step'].astype(int) < 11)]
    .groupby(['vendor','step','substep','stepname','detectiontype']).agg(count=pd.NamedAgg(column="detectiontype", aggfunc="count"))
).reset_index()

# Perecentage of coverage (Telemetry Detection)
substeps_all_count = len(apt29_df['substep'].index)
substeps_telemetry_count = len(apt29_telemetry['substep'].index)
percentage = '{0:.2f}'.format((substeps_telemetry_count / substeps_all_count * 100))

# Visualize
chart = alt.Chart(apt29_grouped).mark_bar().encode(
   alt.Y('stepname:N',sort=alt.EncodingSortField(field="step", order='ascending'), title='Emulation Plan Steps'),
   alt.X('sum(count):Q'),
   alt.Color('step:N', scale=alt.Scale(scheme='dark2')),
   alt.Order('sum(count):Q', sort='ascending')
).properties(
    title='Telemetry Detection Category ({} % Coverage)'.format(percentage)
)

text = chart.mark_text(
    align='left',
    baseline='middle',
    dx=3  # Nudges text to right so it doesn't appear on top of the bar
).encode(text='sum(count):Q')

(chart + text).show()
