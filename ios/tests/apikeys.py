## fufluns - Copyright 2019,2020 - deroad

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
	"secret_key": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "Secret Key found", API_DESCRIPTION: "Generic Secret Key" },
	"private_key": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "Private Key found", API_DESCRIPTION: "Generic Private Key" },
	"privatekey": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "Private Key found", API_DESCRIPTION: "Generic Private Key" },
	"seed": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "Seed found", API_DESCRIPTION: "Generic Seed" },
}

UNK_DETA_KEY  = "Secret Key ({})"
UNK_DESC_KEY  = "Easily discoverable Secret Key ({}) embedded inside {}"
UNK_DETA_PKEY = "Private Key ({})"
UNK_DESC_PKEY = "Easily discoverable Private Key ({}) embedded inside {}"
UNK_DETA_SEED = "Seed ({})"
UNK_DESC_SEED = "Easily discoverable Seed ({}) embedded inside {}"

def test(ipa, plist, u, key, file):
	x = u.dk(plist, key, "")
	if len(x) > 0:
		desc = "Easily discoverable {} embedded inside {}".format(common_api_keys[key][API_DESCRIPTION], file)
		details = format(common_api_keys[key][API_DETAILS], key)
		u.test(ipa, False, details, desc, common_api_keys[key][API_SEVERITY])

def check_in(ipa, plist, u, keys, file):
	prefix = ".".join(keys) + "." if len(keys) > 0 else ""
	for key in plist:
		value = plist[key]
		if "publickey" in key.lower():
			continue
		elif "key" in key.lower() and key not in common_api_keys:
			u.test(ipa, False, UNK_DETA_KEY.format(key), UNK_DESC_KEY.format(prefix + key, file), API_DEFAULT_SEVERITY)
		elif "secret" in key.lower() and key not in common_api_keys:
			u.test(ipa, False, UNK_DETA_KEY.format(key), UNK_DESC_KEY.format(prefix + key, file), API_DEFAULT_SEVERITY)
		elif "seed" in key.lower() and key not in common_api_keys:
			u.test(ipa, False, UNK_DETA_SEED.format(key), UNK_DESC_SEED.format(prefix + key, file), API_DEFAULT_SEVERITY)
		elif "privatekey" in key.lower() and key not in common_api_keys:
			u.test(ipa, False, UNK_DETA_PKEY.format(key), UNK_DESC_PKEY.format(prefix + key, file), API_DEFAULT_SEVERITY)
		elif "private_key" in key.lower() and key not in common_api_keys:
			u.test(ipa, False, UNK_DETA_PKEY.format(key), UNK_DESC_PKEY.format(prefix + key, file), API_DEFAULT_SEVERITY)
		elif isinstance(value, dict):
			keys.append(key)
			check_in(ipa, value, u, keys, file)
			keys.pop()

def run_tests(ipa, r2, u, r2h):
	plists = [f for f in glob.glob(os.path.join(ipa.directory, "Payload", "*", "*.plist"), recursive=True)]
	plist = {}
	for tmp in plists:
		plist = plistlib.readPlist(tmp)
		file = tmp[len(ipa.directory):]
		for key in common_api_keys:
			test(ipa, plist, u, key, file)

		check_in(ipa, plist, u, [], file)

def name_test():
	return "Detection insecure API secrets values"