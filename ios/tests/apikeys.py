## fufluns - Copyright 2019-2021 - deroad

import glob
import os
import re

API_GOOGLE_FILE = "GoogleService-Info.plist"
API_GOOGLE_PROVIDER = "Google"
API_GOOGLE_SEVERITY = 2.5

API_DEFAULT_SEVERITY = 6.5
API_DEFAULT_PROVIDER = "generic"

API_DETAILS     = "details"
API_DESCRIPTION = "description"
API_SEVERITY    = "severity"

common_api_keys = {
	"Fabric.APIKey": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "Fabric.io API Key found", API_DESCRIPTION: "Fabric.io Analytics API Key" },
	"API_KEY_HUB": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "API Key Hub found", API_DESCRIPTION: "Generic API Key Hub" },
}

def test(ipa, plist, u, key):
	x = u.dk(plist, key, "")
	if len(x) > 0:
		desc = "Easily discoverable of {} embedded inside the application Info.plist".format(common_api_keys[key][API_DESCRIPTION])
		u.test(ipa, False, common_api_keys[key][API_DETAILS], desc, common_api_keys[key][API_SEVERITY])

def is_base64(value):
	return re.match(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", value) is not None

def is_uuid(value):
	return re.match(r"^\{?[0-9a-fA-F-]+\}?$", value) is not None

def is_hex(value):
	return re.match(r"^[0-9a-fA-F]+$", value) is not None

def test_recursive(ipa, u, d, file):
	if not isinstance(d, dict):
		return
	for key in d:
		severity = API_DEFAULT_SEVERITY
		provider = API_DEFAULT_PROVIDER
		details  = ""
		descrip  = ""

		if file.endswith(API_GOOGLE_FILE):
			severity = API_GOOGLE_SEVERITY
			provider = API_GOOGLE_PROVIDER

		lkey  = key.lower()
		if key in common_api_keys:
			continue
		value = d[key]
		if isinstance(value, dict):
			test_recursive(ipa, u, value, file)
			continue
		elif not isinstance(value, str):
			continue
		elif ("api_key" in lkey or "apikey" in lkey) and " " not in value:
			details = "Insecure storage of a {} API key in application resource.".format(provider)
			descrip = "Easily discoverable API key ({}: {}) embedded inside {}".format(key, value, file)
		elif ("privatekey" in lkey or "private_key" in lkey) and " " not in value:
			details = "Insecure storage of a {} Private Key in application resource.".format(provider)
			descrip = "Easily discoverable Private Key ({}: {}) embedded inside {}".format(key, value, file)
		elif "secret" in lkey and " " not in value:
			details = "Insecure storage of a {} Secret in application resource.".format(provider)
			descrip = "Easily discoverable Secret ({}: {}) embedded inside {}".format(key, value, file)
		elif ("appkey" in lkey or "app_key" in lkey) and " " not in value:
			details = "Insecure storage of a {} Application Key in application resource.".format(provider)
			descrip = "Easily discoverable Application Key ({}: {}) embedded inside {}".format(key, value, file)
		elif "password" in lkey and (is_base64(value) or is_uuid(value) or is_hex(value)):
			details = "Insecure storage of a {} Password in application resource.".format(provider)
			descrip = "Easily discoverable Password ({}: {}) embedded inside {}".format(key, value, file)
		elif "token" in lkey and (is_base64(value) or is_uuid(value) or is_hex(value)):
			details = "Insecure storage of a {} Token in application resource.".format(provider)
			descrip = "Easily discoverable Token ({}: {}) embedded inside {}".format(key, value, file)
		elif "seed" in lkey and (is_base64(value) or is_uuid(value) or is_hex(value)):
			details = "Insecure storage of a {} Seed in application resource.".format(provider)
			descrip = "Easily discoverable Seed ({}: {}) embedded inside {}".format(key, value, file)
		elif "nonce" in lkey and (is_base64(value) or is_uuid(value) or is_hex(value)):
			details = "Insecure storage of a {} Nonce in application resource.".format(provider)
			descrip = "Easily discoverable Nonce ({}: {}) embedded inside {}".format(key, value, file)

		if len(descrip) > 0 and len(details) > 0:
			u.test(ipa, False, details, descrip, severity)


def run_tests(ipa, pipe, u, rzh):
	tmp = [f for f in glob.glob(os.path.join(ipa.directory, "Payload", "*", "Info.plist"), recursive=True)]
	plist = {}
	if len(tmp) > 0:
		plist = u.load_plist(tmp[0])

	for key in common_api_keys:
		test(ipa, plist, u, key)

	plists = glob.glob(os.path.join(ipa.directory, "**", "*.plist"), recursive=True)
	for file in plists:
		plist = u.load_plist(file)
		test_recursive(ipa, u, plist, file[len(ipa.directory):])

def name_test():
	return "Detection insecure API secrets values"
