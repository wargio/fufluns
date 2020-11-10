## fufluns - Copyright 2020 - deroad

import os
import xml.etree.ElementTree as ET
import urllib3
import re

urllib3.disable_warnings()

## CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N
SEVERITY = 7.1
DESCRIPTION = "Firebase Real-time Databases contains sensitive information on their users, including their email addresses, usernames, passwords, phone numbers, full names, chat messages and location data."

FIREBASE_REGEX = r'https*://(.+?)\.firebaseio.com'

def run_tests(apk, r2s, u, r2h, au):
	projects = []
	misconfigured = []

	file = os.path.join("res", "values", "strings.xml")
	manifest = os.path.join(apk.apktool, file)
	root = ET.parse(manifest).getroot()
	tags = root.findall("string")

	for tag in tags:
		if tag.text == None:
			continue
		project = re.findall(FIREBASE_REGEX, tag.text.strip())
		if len(project) > 0:
			projects.extend(project)

	apk.logger.notify("Found {} firebaseio.com projects.".format(len(projects)))

	http = urllib3.PoolManager()
	for project in projects:
		url = 'https://{}.firebaseio.com/.json'.format(project)
		try:
			resp = http.request('GET', url)
			if resp.status == 200:
				misconfigured.append(project)
			elif resp.status == 401:
				apk.logger.info("[OK] https://{}.firebaseio.com is secure.".format(project))
			elif resp.status == 404:
				apk.logger.notify("[--] https://{}.firebaseio.com/ was not found.".format(project))
		except urllib3.URLError:
			apk.logger.error("No network connection. Please check the network connectivity.")
			return
	msg = "Misconfigured firebaseio instance {0} over {1} found.".format(len(misconfigured), len(projects))
	u.test(apk, len(misconfigured) < 1, msg, DESCRIPTION, SEVERITY)

def name_test():
	return "Misconfigured Firebaseio Instance"