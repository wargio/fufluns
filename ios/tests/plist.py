## fufluns - Copyright 2019-2021 - deroad

import glob
import os
import json

def run_tests(ipa, pipe, u, rzh):
	plists = glob.glob(os.path.join(ipa.directory, "**", "*.plist"), recursive=True)
	for file in plists:
		plist = u.load_plist(file)
		plist = json.dumps(plist, indent=4, default=lambda o: '<not serializable>')
		ipa.extra.add(file[len(ipa.directory):], plist)
	ipa.logger.notify("Found {} plists.".format(len(plists)))


def name_test():
	return "Decoding plists"