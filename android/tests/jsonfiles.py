import glob
import os
import json

def run_tests(apk, r2, u, r2h):
	jsons = glob.glob(os.path.join(apk.unzip, "**", "*.json"), recursive=True)
	for file in jsons:
		with open(file, "rb") as fp:
			try:
				data = json.dumps(json.load(fp), indent=4)
				apk.extra.add(file[len(apk.unzip):], data)
			except Exception:
				pass
	apk.logger.notify("Found {} JSONs.".format(len(jsons)))


def name_test():
	return "Decoding JSONs"