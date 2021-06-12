## fufluns - Copyright 2019-2021 - deroad

import os
import re
import xml.etree.ElementTree as ET

API_GOOGLE_SEVERITY = 2.5
API_DEFAULT_SEVERITY = 6.5

API_DETAILS     = "details"
API_DESCRIPTION = "description"
API_SEVERITY    = "severity"

common_api_keys = {
	"google_api_key": { API_SEVERITY: API_GOOGLE_SEVERITY, API_DETAILS: "Google API Key found", API_DESCRIPTION: "Google API Key" },
	"google_maps_key": { API_SEVERITY: API_GOOGLE_SEVERITY, API_DETAILS: "Google Maps Key found", API_DESCRIPTION: "Google Maps Key" },
	"google_crash_reporting_api_key": { API_SEVERITY: API_GOOGLE_SEVERITY, API_DETAILS: "Google Crash Report found", API_DESCRIPTION: "Google Crash Report API Key" },
	"seed_crypto_keystore_password": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "Seed Crypto Keystore Password found", API_DESCRIPTION: "Seed Crypto Keystore Password" },
	"seed_crypto_privatekey_alias": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "Seed Crypto Privatekey Alias found", API_DESCRIPTION: "Seed Crypto Privatekey Alias" },
	"seed_crypto_privatekey_password": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "Seed Crypto Privatekey Password found", API_DESCRIPTION: "Seed Crypto Privatekey Password" },
	"zendesk_chat_key": { API_SEVERITY: API_DEFAULT_SEVERITY, API_DETAILS: "ZenDesk Key found", API_DESCRIPTION: "ZenDesk Key" },
}

def is_base64(value):
	return re.match(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", value) is not None

def is_uuid(value):
	return re.match(r"^\{?[0-9a-fA-F-]+\}?$", value) is not None

def is_hex(value):
	return re.match(r"^[0-9a-fA-F]+$", value) is not None

def run_tests(apk, pipes, u, rzh, au):
	file = os.path.join("res", "values", "strings.xml")
	manifest = os.path.join(apk.apktool, file)
	root = ET.parse(manifest).getroot()
	tags = root.findall("string")
	for tag in tags:
		severity = API_DEFAULT_SEVERITY
		details  = ""
		descrip  = ""
		if 'name' not in tag.attrib or tag.text is None:
			continue
		value = tag.text.strip();
		key   = tag.attrib['name']
		lkey  = key.lower()
		if key in common_api_keys:
			details  = common_api_keys[key][API_DETAILS]
			severity = common_api_keys[key][API_SEVERITY]
			descrip  = "Easily discoverable of {} ({}: {}) embedded inside {}".format(common_api_keys[key][API_DESCRIPTION], key, value, file)
		elif ("api_key" in lkey or "apikey" in lkey) and " " not in value:
			details = "Insecure storage of a generic API key in application resource."
			descrip = "Easily discoverable API key ({}: {}) embedded inside {}".format(key, value, file)
		elif ("privatekey" in lkey or "private_key" in lkey) and " " not in value:
			details = "Insecure storage of a generic Private Key in application resource."
			descrip = "Easily discoverable Private Key ({}: {}) embedded inside {}".format(key, value, file)
		elif "secret" in lkey and " " not in value:
			details = "Insecure storage of a generic Secret in application resource."
			descrip = "Easily discoverable Secret ({}: {}) embedded inside {}".format(key, value, file)
		elif ("appkey" in lkey or "app_key" in lkey) and " " not in value:
			details = "Insecure storage of a generic Application Key in application resource."
			descrip = "Easily discoverable Application Key ({}: {}) embedded inside {}".format(key, value, file)
		elif "password" in lkey and (is_base64(value) or is_uuid(value) or is_hex(value)):
			details = "Insecure storage of a generic Password in application resource."
			descrip = "Easily discoverable Password ({}: {}) embedded inside {}".format(key, value, file)
		elif "token" in lkey and (is_base64(value) or is_uuid(value) or is_hex(value)):
			details = "Insecure storage of a generic Token in application resource."
			descrip = "Easily discoverable Token ({}: {}) embedded inside {}".format(key, value, file)
		elif "seed" in lkey and (is_base64(value) or is_uuid(value) or is_hex(value)):
			details = "Insecure storage of a generic Seed in application resource."
			descrip = "Easily discoverable Seed ({}: {}) embedded inside {}".format(key, value, file)
		elif "nonce" in lkey and (is_base64(value) or is_uuid(value) or is_hex(value)):
			details = "Insecure storage of a generic Nonce in application resource."
			descrip = "Easily discoverable Nonce ({}: {}) embedded inside {}".format(key, value, file)

		if len(descrip) > 0 and len(details) > 0:
			u.test(apk, False, details, descrip, severity)

def name_test():
	return "Detection insecure API secrets values"
