import os
import xml.etree.ElementTree as ET

TRUES = ["true"]

DEBUGGABLE_APP_KEYS        = ["application"]
DEBUGGABLE_APP_ISSUE       = "The application has debuggable activities."
DEBUGGABLE_APP_DESCRIPTION = "Android allows the attribute android:debuggable to be set to true in the manifest, so that the app can be debugged"
DEBUGGABLE_APP_SEVERITY    = 4.8

EXPORT_RCV_KEYS        = ["receiver", "provider", "activity"]
EXPORT_RCV_ISSUE       = "The application has exposed exported {}.".format("/".join(EXPORT_RCV_KEYS))
EXPORT_RCV_DESCRIPTION = "It should be explicitly disallowed other developers apps from accessing the ContentProvider objects that the app contains (unless required)."
EXPORT_RCV_SEVERITY    = 5.3

def find_any(apk, u, root, keys, attval, keywords, issue, descr, severity):
	attval = "{http://schemas.android.com/apk/res/android}" + attval
	found = 0
	for key in keys:
		tags = root.findall(key)
		for tag in tags:
			for att in tag.attrib:
				if att != attval:
					continue
				value = tag.attrib[att]
				if value in keywords:
					found += 1
	if found > 0:
		u.test(apk, False, DEBUGGABLE_APP_ISSUE, DEBUGGABLE_APP_DESCRIPTION, DEBUGGABLE_APP_SEVERITY)

def run_tests(apk, r2s, u, r2h, au):
	manifest = os.path.join(apk.apktool, "AndroidManifest.xml")
	root = ET.parse(manifest).getroot()
	find_any(apk, u, root, DEBUGGABLE_APP_KEYS, "debuggable", TRUES, DEBUGGABLE_APP_ISSUE, DEBUGGABLE_APP_DESCRIPTION, DEBUGGABLE_APP_SEVERITY)
	find_any(apk, u, root, EXPORT_RCV_KEYS    , "exported"  , TRUES, EXPORT_RCV_ISSUE    , EXPORT_RCV_DESCRIPTION    , EXPORT_RCV_SEVERITY    )

def name_test():
	return "Detection interesting tag flags in AndroidManifest.xml"
