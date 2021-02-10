## fufluns - Copyright 2019-2021 - deroad

import glob
import os
import json

SKIP_FILES = [
	'/font/',
	'/Font/',
	'/fonts/',
	'/Fonts/',
]

def run_tests(ipa, pipe, u, rzh):
	jsons = glob.glob(os.path.join(ipa.directory, "**", "*.json"), recursive=True)
	for file in jsons:
		skip_file = False
		for skip in SKIP_FILES:
			if skip in file:
				skip_file = True
				break
		if skip_file:
			continue
		try:
			with open(file, "rb") as fp:
				data = json.dumps(json.load(fp), indent=4)
				ipa.extra.add(file[len(ipa.directory):], data)
		except Exception:
			with open(file, "r") as fp:
				data = fp.read().strip()
				ipa.extra.add(file[len(ipa.directory):], data)
	ipa.logger.notify("Found {} JSONs.".format(len(jsons)))


def name_test():
	return "Decoding JSONs"