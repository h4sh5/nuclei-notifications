#!/usr/bin/env python3

import requests
import yaml # pip3 install pyyaml
import os
import sys
from urllib.parse import quote_plus

# discord webhook
WEBHOOK = os.getenv("WEBHOOK")
WEBHOOK1 = os.getenv("WEBHOOK1")
SHODAN_API = os.getenv("SHODAN_API")

r = requests.get('https://github.com/projectdiscovery/nuclei-templates/raw/main/.new-additions')
old_additions = ''
if os.path.exists('new-additions.txt'):
	with open('new-additions.txt', 'r') as f:
		old_additions = f.read()
		old_additions = old_additions.split()
with open('new-additions.txt', 'w') as f:
	f.write(r.text)


def get_shodan_query_count(query):
	'''
	count the total stats about a query, return a stat string
	'''
	all_total = -1
	au_total = -1
	query = quote_plus(query)
	au_only = f"{query}+country:AU"
	url = f"https://api.shodan.io/shodan/host/count?query={query}&key={SHODAN_API}"
	r = requests.get(url)
	if r.status_code == 200:
		d = r.json()
		all_total = d.get("total")

	au_url = f"https://api.shodan.io/shodan/host/count?query={au_only}&key={SHODAN_API}"
	r = requests.get(au_url)
	if r.status_code == 200:
		d = r.json()
		au_total = d.get("total")

	return f"g:{all_total} au:{au_total}"

messages = []

notification_msg = ''

for template_file in r.text.split('\n'):

	try:

		template_file = template_file.strip()

		if template_file in old_additions:
			print(f"skipping old file {template_file}")
			continue
		cve = f'{template_file.split("/")[-1].split(".yaml")[0]}'
		# nvd and github urls for quick checking
		notification_line = f'[{cve}](https://nvd.nist.gov/vuln/detail/{cve}) [(tpl)](https://github.com/projectdiscovery/nuclei-templates/blob/main/{template_file}) '
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
							shodan_part += "\n```\n"
							for query in template['info']['metadata'].get('shodan-query'):
								count_str = get_shodan_query_count(query)
								shodan_part += f"`{query}`" + f" #{count_str}" + "\n"
							shodan_part += "\n```\n"

						else:
							query = template['info']['metadata'].get('shodan-query')
							count_str = get_shodan_query_count(query)
							shodan_part += f"`{query}` #{count_str}\n"

				tags = template['info'].get('tags')
				tags_part = ''
				if tags:
					tags_part = str(template['info'].get('tags'))

				if "rce" in tags.lower() or "execution" in name.lower() or "rce" in name.lower():
					crit = True
			notification_line = name + " " + notification_line + " " +  cvss_part + shodan_part + "tags: " +  tags_part
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

if len(notification_line) > 0:
	messages.append(notification_msg)

# deal with content limits
print(f"sending {len(messages)} messages..")
for m in messages:
	print(m)
	if WEBHOOK != None:
		r = requests.post(WEBHOOK, json={"content":m})
	if WEBHOOK1 != None:
		r = requests.post(WEBHOOK1, json={"content":m})

