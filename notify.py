#!/usr/bin/env python3

import requests
import yaml # pip3 install pyyaml
import os
import sys

# discord webhook
WEBHOOK = os.getenv("WEBHOOK")


r = requests.get('https://github.com/projectdiscovery/nuclei-templates/raw/main/.new-additions')
old_additions = ''
if os.path.exists('new-additions.txt'):
	with open('new-additions.txt', 'r') as f:
		old_additions = f.read()
		old_additions = old_additions.split()
with open('new-additions.txt', 'w') as f:
	f.write(r.text)

messages = []

notification_msg = ''

for template_file in r.text.split('\n'):

	try:

		template_file = template_file.strip()

		if template_file in old_additions:
			print(f"skipping old file {template_file}")
			continue

		notification_line = f'{template_file.split("/")[-1].split(".yaml")[0]} '
		shodan_part = ''
		cvss_part = ''
		name = ''
		crit = False
		if "CVE-" in template_file.upper():
			print("processing:", template_file)
			rawurl = f'https://github.com/projectdiscovery/nuclei-templates/raw/main/{template_file}'
			
			r = requests.get(rawurl)

			template = yaml.safe_load(r.text)


			if 'info' in template:
				name = template['info'].get('name')

				if template['info'].get('classification'):
					if template['info']['classification'].get('cvss-score'):
						cvss_part = " cvss: " + str(template['info']['classification'].get('cvss-score'))
						if float(template['info']['classification'].get('cvss-score')) > 8:
							cvss_part += ":red_circle:"
						cvss_part += " "

				if template['info'].get('metadata'):
					if template['info']['metadata'].get('shodan-query') != None:
						shodan_part = "\nshodan:"
						if type(template['info']['metadata'].get('shodan-query') ) == list:
							shodan_part += "\n```\n" + '\n'.join(template['info']['metadata'].get('shodan-query')) + "\n```\n"
						else:
							shodan_part += f"`{template['info']['metadata'].get('shodan-query')}`\n"

				tags = template['info'].get('tags')
				tags_part = ''
				if tags:
					tags_part = str(template['info'].get('tags'))

				if "rce" in tags.lower() or "execution" in name.lower() or "rce" in name.lower():
					crit = True
			notification_line += name  + cvss_part + shodan_part + "tags: " +  tags_part
			if crit:
				notification_line = ":fire: " + notification_line
			if (len(notification_msg) + len(notification_line)) > 2000:
				messages.append(notification_msg)
				# reset notification msg
				notification_msg = notification_line + "\n" + "-" * 5 + "\n" 

			else:
				notification_msg += notification_line + "\n" + "-" * 5 + "\n" 

	except Exception as e:
		print("ERROR: ", e, flush=True)

messages.append(notification_msg)

# deal with content limits
print(f"sending {len(messages)} messages..")
for m in messages:
	print(m)
	if WEBHOOK != None:
		r = requests.post(WEBHOOK, json={"content":m})

