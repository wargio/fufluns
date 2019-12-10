import glob
import os
import json

SKIP_FILES = [
	'/font/',
	'/Font/',
	'/fonts/',
	'/Fonts/',
]

def run_tests(apk, r2, u, r2h):
	jsons = glob.glob(os.path.join(apk.unzip, "**", "*.json"), recursive=True)
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
				apk.extra.add(file[len(apk.unzip):], data)
		except Exception:
			with open(file, "r") as fp:
				data = fp.read().strip()
				apk.extra.add(file[len(apk.unzip):], data)
	apk.logger.notify("Found {} JSONs.".format(len(jsons)))


def name_test():
	return "Decoding JSONs"