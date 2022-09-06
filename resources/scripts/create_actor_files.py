from jinja2 import Template
import copy
from attackcti import attack_client

# ******** Open actor group template ****************
print("[+] Reading master actor group template..")
group_template = Template(open('templates/actor_template.md').read())

# ******** Retrieving ATT&CK Groups ****************
print("[+] Retrieving all actor groups from ATT&CK")
lift = attack_client()
techniques_used = lift.get_techniques_used_by_all_groups()
groups = lift.get_groups()
groups = lift.remove_revoked(groups)

print("\n[+] Grouping techniques by specific actor group..")
groups_list = []
for g in groups:
    groupDict = {
        "name" : g['name'],
        "description" : g['description'],
        "group_id" : g['external_references'][0]['external_id'],
        "techniques" : []
    }
    groups_list.append(groupDict)      
for group in groups_list:
    print("  [>>] Grouping techniques for {} actor..".format(group['name']))
    for gut in techniques_used:
        if group['name'] == gut['name']:
            techniqueDict = {
                "techniqueId" : gut['technique_id'],
                "techniqueName" : gut['technique'],
                "relationshipComment" : gut['relationship_description'],
                "tactics" : gut['tactic']
            }
            if 'data_sources' in gut:
                techniqueDict['dataSources'] = gut['data_sources']
            if 'platform' in gut:
                techniqueDict['platform'] = gut['platform']
            group['techniques'].append(techniqueDict)

print("\n[+] Writing results to markdown ..")
for group in groups_list:
    group_for_render = copy.deepcopy(group)
    # Generate the markdown
    markdown = group_template.render(group=group_for_render)

    print("  [>>] writing {} group information to {}.md..".format(group['name'], group['group_id']))
    # Save to the group page
    open('../docs/content/cti/{}.md'.format(group['group_id']), 'w').write(markdown)
