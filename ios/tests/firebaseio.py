## fufluns - Copyright 2021 - deroad

import glob
import os
import urllib3
import re

urllib3.disable_warnings()

## CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N
SEVERITY = 7.1
DESCRIPTION = "Firebase Real-time Databases contains sensitive information on their users, including their email addresses, usernames, passwords, phone numbers, full names, chat messages and location data."
NO_NETWORK = "No network connection. Please check the network connectivity."
FIREBASE_REGEX = rb'https*://(.+?)\.firebaseio.com'

def iterate_object(obj):
	projects = []
	if isinstance(obj, list):
		for value in obj:
			if isinstance(value, (list, dict)):
				projects.extend(iterate_object(value))
				continue
			elif not isinstance(value, str):
				continue
			value = value.encode('utf-8')
			project = re.findall(FIREBASE_REGEX, value)
			if len(project) > 0:
				projects.extend(project)
	else:
		for key in obj:
			value = obj[key]
			if isinstance(value, (list, dict)):
				projects.extend(iterate_object(value))
				continue
			elif not isinstance(value, str):
				continue
			value = value.encode('utf-8')
			project = re.findall(FIREBASE_REGEX, value)
			if len(project) > 0:
				projects.extend(project)
	return projects

def run_tests(ipa, rz, u, rzh):
	projects = []
	misconfigured = []
	plists = glob.glob(os.path.join(ipa.directory, "**", "*.plist"), recursive=True)
	for file in plists:
		plist = u.load_plist(file)
		projects.extend(iterate_object(plist))

	projects = list(filter(lambda x: len(x) > 0, projects))

	ipa.logger.notify("Found {} firebaseio.com projects.".format(len(projects)))

	if len(projects) > 0:
		http = urllib3.PoolManager()
		for project in projects:
			project = project.decode('utf-8')
			url = 'https://{}.firebaseio.com/.json'.format(project)
			try:
				resp = http.request('GET', url)
				if resp.status == 200:
					misconfigured.append(project)
					ipa.logger.warning("[XX] https://{}.firebaseio.com/ is insecure.".format(project))
				elif resp.status == 401:
					ipa.logger.info("[OK] https://{}.firebaseio.com/ is secure.".format(project))
				elif resp.status == 404:
					ipa.logger.notify("[--] https://{}.firebaseio.com/ was not found.".format(project))
			except urllib3.exceptions.NewConnectionError:
				ipa.logger.error(NO_NETWORK)
				return
			except urllib3.exceptions.MaxRetryError:
				ipa.logger.error(NO_NETWORK)
				return
			url = 'https://firestore.googleapis.com/v1/projects/{}/databases/(default)/'.format(project)
			try:
				resp = http.request('GET', url)
				if resp.status == 200:
					misconfigured.append(project)
					ipa.logger.warning("[XX] https://firestore.googleapis.com/v1/projects/{}/databases/(default)/ is insecure.".format(project))
				elif resp.status == 401:
					ipa.logger.info("[OK] https://firestore.googleapis.com/v1/projects/{}/databases/(default)/ is secure.".format(project))
				elif resp.status == 404:
					ipa.logger.notify("[--] https://firestore.googleapis.com/v1/projects/{}/databases/(default)/ was not found.".format(project))
			except urllib3.exceptions.NewConnectionError:
				ipa.logger.error(NO_NETWORK)
				return
			except urllib3.exceptions.MaxRetryError:
				ipa.logger.error(NO_NETWORK)
				return

	verb = "found"
	if len(misconfigured) < 1:
		verb = "not found"

	msg = "Misconfigured firebaseio instance {}.".format(verb)
	u.test(ipa, len(misconfigured) < 1, msg, DESCRIPTION, SEVERITY)

def name_test():
	return "Misconfigured Firebaseio Instance"