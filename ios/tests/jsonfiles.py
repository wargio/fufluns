import glob
import os
import json

def run_tests(apk, r2, u, r2h):
	jsons = glob.glob(os.path.join(apk.directory, "**", "*.json"), recursive=True)
	for file in jsons:
		try:
			with open(file, "rb") as fp:
				data = json.dumps(json.load(fp), indent=4)
				apk.extra.add(file[len(apk.directory):], data)
		except Exception:
			with open(file, "r") as fp:
				data = fp.read().strip()
				apk.extra.add(file[len(apk.directory):], data)
	apk.logger.notify("Found {} JSONs.".format(len(jsons)))


def name_test():
	return "Decoding JSONs"