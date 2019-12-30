import os

def run_tests(apk, r2s, u, r2h, au):
	manifest = os.path.join(apk.apktool, "AndroidManifest.xml")
	with open(manifest, "r") as fp:
		apk.extra.add("AndroidManifest.xml", "".join(fp.readlines()))
		apk.logger.notify("AndroidManifest found.")

def name_test():
	return "Dumping AndroidManifest.xml"