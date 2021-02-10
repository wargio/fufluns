## fufluns - Copyright 2019-2021 - deroad

import os

def run_tests(apk, pipes, u, rzh, au):
	manifest = os.path.join(apk.apktool, "AndroidManifest.xml")
	apk.extra.add_text_file(manifest)
	apk.logger.notify("AndroidManifest found.")

def name_test():
	return "Dumping AndroidManifest.xml"