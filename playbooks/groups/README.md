# Adversary Attribution
This section of the ThreatHunter-Playbook is a summary of all the groups identified in the MITRE ATTACK Framework. According to the MITRE ATTACK team, "groups are sets of related intrusion activity that are tracked by a common name in the security community. Groups are also sometimes referred to as campaigns or intrusion sets. Some groups have multiple names associated with the same set of activities due to various organizations tracking the same set of activities by different names. Groups are mapped to publicly reported technique use and referenced in the ATT&CK threat model. Groups are also mapped to reported software used during intrusions".

One of things that I found very useful when using the MITRE ATTACK API, is the ability to merge several pages of data into one table. As you know, MITRE has groups mapped to TTPs and Software, but the definitions of Software in relation to each group are in separate pages. I used the API and created tables of TTPs and Software with the respective definitions attributed to each group.

# Goals
* Expedite the development of Adversary hunting campaigns.
* Help Threat Hunters understand and learn patterns of behavior per each Group.
* Learn a little bit more about the MITRE API and share the results with others in the community.


# How do I use it?
* Pick the adversary/Group you want to hunt for
* Open the file associated with the Groups Name
* Learn about the TTPs and Tools attributed to it
* Use the Excel Sheet found [HERE](https://github.com/Cyb3rWard0g/Invoke-ATTACKAPI/blob/master/examples/ATTACK_ALL.xlsx) to have a 360 view of your adversary and get more information for your hunting campaign (i.e. Data sources, Analytic Details, etc). 

# Author
* Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

# Contributors
