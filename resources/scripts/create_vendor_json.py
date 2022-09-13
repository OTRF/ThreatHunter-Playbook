import json
import glob
from os import path

json_files = glob.glob(path.join(path.dirname(__file__), '../../joystick/data/evaluations/apt29', "*.json"))
vendor_list = []
for jf in json_files:
    vendor = path.basename(jf).split(".")[0]
    with open(jf,'r') as fi:
        dict = json.load(fi)
        for t in dict['Techniques']:
            for s in t['Steps']:
                for d in s['Detections']:
                    vendorDict = {
                        "vendor" : vendor,
                        "step" : s['SubStep'].split(".")[0],
                        "substep" : s['SubStep'],
                        "techniqueid" : t['TechniqueId'],
                        "techniquename" : t['TechniqueName'],
                        "detectiontype" : d['DetectionType'],
                        "detectionotes" : d['DetectionNote']
                    }
                    vendor_list.append(vendorDict)
# Write Results
with open('../docs/evals/apt29/data/vendor_results.json', 'w') as results:
    json.dump(vendor_list, results)
