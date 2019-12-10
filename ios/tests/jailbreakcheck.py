import glob
import os
import plistlib

DESCRIPTION = "Applications on a jailbroken device run as root outside of the iOS sandbox. This can allow applications to access sensitive data contained in other apps or install malicious software that compromise the user data."
SEVERITY    = 6.7

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

	if len(tmp) > 0:
		ipa.logger.notify("Schema[s] found: {}".format('://,'.join(tmp) + '://'))

	for schema in tmp:
		if schema in queryschemas:
			found.append(schema + "://")

	message = "Jailbreak/Root check is missing"
	if len(found) > 0:
		message = "Jailbreak/Root check found via schemas {}".format(", ".join(found))

	u.test(ipa, len(found) > 0, message, DESCRIPTION, SEVERITY)

def name_test():
	return "Detection Jailbreak/Root"