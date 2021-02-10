## fufluns - Copyright 2019-2021 - deroad

import glob
import os
import plistlib

API_DEFAULT_SEVERITY = 6.5

API_DETAILS     = "details"
API_DESCRIPTION = "description"
API_SEVERITY    = "severity"

common_api_keys = {
	"Fabric.APIKey": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "Fabric.io API Key found", API_DESCRIPTION: "Fabric.io Analytics API Key" },
	"API_KEY_HUB": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "API Key Hub found", API_DESCRIPTION: "Generic API Key" },
	"API_KEY": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "API Key found", API_DESCRIPTION: "Generic API Key" },
	"Api_Key": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "API Key found", API_DESCRIPTION: "Generic API Key" },
	"api_key": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "API Key found", API_DESCRIPTION: "Generic API Key" },
}

def test(ipa, plist, u, key):
	x = u.dk(plist, key, "")
	if len(x) > 0:
		desc = "Easily discoverable of {} embedded inside the application Info.plist".format(common_api_keys[key][API_DESCRIPTION])
		u.test(ipa, False, common_api_keys[key][API_DETAILS], desc, common_api_keys[key][API_SEVERITY])

def run_tests(ipa, pipe, u, rzh):
	tmp = [f for f in glob.glob(os.path.join(ipa.directory, "Payload", "*", "Info.plist"), recursive=True)]
	plist = {}
	if len(tmp) > 0:
		plist = plistlib.readPlist(tmp[0])

	for key in common_api_keys:
		test(ipa, plist, u, key)

def name_test():
	return "Detection insecure API secrets values"