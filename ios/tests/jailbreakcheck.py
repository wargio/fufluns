


import glob
import os
import plistlib

queryschemas = {
	'cydia',
	'undecimus',
	'sileo',
}

def has_permission(ipa, plist, u, permission, description):
	p = u.dk(plist, permission, description)
	if len(p) > 0:
		u.permission(ipa, permission, description)

def run_tests(ipa, r2, u, r2h):
	tmp = [f for f in glob.glob(os.path.join(ipa.directory, "Payload", "*", "Info.plist"), recursive=True)]
	plist = {}
	if len(tmp) > 0:
		plist = plistlib.readPlist(tmp[0])

	tmp = u.dk(plist, "LSApplicationQueriesSchemes", [])
	found = []
	for schema in queryschemas:
		if schema in tmp:
			found.append(schema + "://")

	message = "Jailbreak/Root check via canOpenURL is missing"
	if len(found) > 0:
		message = "Jailbreak/Root check via canOpenURL found via schemas {}".format(", ".join(found))

	u.test(ipa, len(found) > 0, message, "MISSING", 5)

def name_test():
	return "Detection Jailbreak/Root"