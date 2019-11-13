import glob
import os
import plistlib

API_DEFAULT_SEVERITY = 4

API_DETAILS     = "details"
API_DESCRIPTION = "description"
API_SEVERITY    = "severity"

common_api_keys = {
	"Fabric.APIKey": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "Fabric.io API Key found", API_DESCRIPTION: "Fabric.io Analytics" },
}

def test(ipa, plist, u, key):
	x = u.dk(plist, key, "")
	if len(x) > 0:
		u.test(ipa, False, common_api_keys[key][API_DETAILS], common_api_keys[key][API_DESCRIPTION], common_api_keys[key][API_SEVERITY])

def run_tests(ipa, r2, u, r2h):
	tmp = [f for f in glob.glob(os.path.join(ipa.directory, "Payload", "*", "Info.plist"), recursive=True)]
	plist = {}
	if len(tmp) > 0:
		plist = plistlib.readPlist(tmp[0])

	for key in common_api_keys:
		test(ipa, plist, u, key)

def name_test():
	return "Detection insecure API secrets values"