## fufluns - Copyright 2019,2020 - deroad

import glob
import os
import plistlib

API_DEFAULT_SEVERITY = 6.5

API_DETAILS     = "details"
API_DESCRIPTION = "description"
API_SEVERITY    = "severity"

COMMON_DESC = "Easily discoverable {} ({}: {}) embedded inside {}"

COMMON_API_KEYS = {
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

UNK_DETA_KEY  = "Secret Key"
UNK_DETA_PKEY = "Private Key"
UNK_DETA_SEED = "Seed"

def test(ipa, plist, u, key, file):
	value = u.dk(plist, key, "")
	if len(value) > 0:
		desc = COMMON_DESC.format(COMMON_API_KEYS[key][API_DESCRIPTION], key, value, file)
		details = COMMON_API_KEYS[key][API_DETAILS]
		u.test(ipa, False, details, desc, COMMON_API_KEYS[key][API_SEVERITY])

def check_in(ipa, plist, u, keys, file):
	prefix = ".".join(keys) + "." if len(keys) > 0 else ""
	index = -1
	for key in plist:
		index += 1
		if isinstance(key, dict):
			keys.append(str(index))
			check_in(ipa, key, u, keys, file)
			keys.pop()
			continue
		elif not isinstance(key, str):
			continue
		value = plist[key]
		if "publickey" in key.lower() or (isinstance(value, str) and len(value.strip()) < 1):
			continue
		elif "key" in key.lower() and key not in COMMON_API_KEYS:
			u.test(ipa, False, UNK_DETA_KEY + " found", COMMON_DESC.format(UNK_DETA_KEY, prefix + key, value.strip(), file), API_DEFAULT_SEVERITY)
		elif "secret" in key.lower() and key not in COMMON_API_KEYS:
			u.test(ipa, False, UNK_DETA_KEY + " found", COMMON_DESC.format(UNK_DETA_KEY, prefix + key, value.strip(), file), API_DEFAULT_SEVERITY)
		elif "seed" in key.lower() and key not in COMMON_API_KEYS:
			u.test(ipa, False, UNK_DETA_SEED + " found", COMMON_DESC.format(UNK_DETA_SEED, prefix + key, value.strip(), file), API_DEFAULT_SEVERITY)
		elif "privatekey" in key.lower() and key not in COMMON_API_KEYS:
			u.test(ipa, False, UNK_DETA_PKEY + " found", COMMON_DESC.format(UNK_DETA_PKEY, prefix + key, value.strip(), file), API_DEFAULT_SEVERITY)
		elif "private_key" in key.lower() and key not in COMMON_API_KEYS:
			u.test(ipa, False, UNK_DETA_PKEY + " found", COMMON_DESC.format(UNK_DETA_PKEY, prefix + key, value.strip(), file), API_DEFAULT_SEVERITY)
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
		for key in COMMON_API_KEYS:
			test(ipa, plist, u, key, file)

		check_in(ipa, plist, u, [], file)

def name_test():
	return "Detection insecure API secrets values"