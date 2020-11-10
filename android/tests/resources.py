## fufluns - Copyright 2020 - deroad

import glob
import os

SKIP_FILES = [
	'/res/anim'
	'/res/color',
	'/res/drawable',
	'/res/layout',
	'/res/mipmap',
	'/res/menu'
]

def can_skip(file):
	for prefix in SKIP_FILES:
		if file.startswith(prefix):
			return True
	return False

def run_tests(apk, r2, u, r2h, au):
	files = glob.glob(os.path.join(apk.apktool, "**", "*.xml"), recursive=True)
	dirlen = len(apk.apktool)
	resources = 0
	for file in files:
		fpath = file[dirlen:]

		if can_skip(fpath):
			continue

		resources += 1
		with open(file, 'r', errors='replace') as fp:
			text = "".join(fp.readlines())
			apk.extra.add(fpath, text)
	apk.logger.notify("Found {} resources.".format(resources))



def name_test():
	return "Application resources"
	
