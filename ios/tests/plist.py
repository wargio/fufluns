## fufluns - Copyright 2019,2020 - deroad

import glob
import os
import plistlib
import json

def run_tests(ipa, r2, u, r2h):
	plists = glob.glob(os.path.join(ipa.directory, "**", "*.plist"), recursive=True)
	for file in plists:
		plist = plistlib.readPlist(file)
		plist = json.dumps(plist, indent=4, default=u.not_serializable)
		ipa.extra.add(file[len(ipa.directory):], plist)
	ipa.logger.notify("Found {} plists.".format(len(plists)))


def name_test():
	return "Decoding plists"