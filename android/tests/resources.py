## fufluns - Copyright 2021 - deroad

import glob
import os

SKIP_FILES = [
	'/res/anim',
	'/res/color',
	'/res/colour',
	'/res/drawable',
	'/res/font',
	'/res/layout',
	'/res/menu',
	'/res/mipmap',
	# langs usually are `/res/values-en` `/res/values-fr`..
	'/res/values-',
	# fullpaths
	'/original/AndroidManifest.xml',
	'/res/values/colors.xml',
	'/res/values/dimens.xml',
	'/res/values/drawables.xml',
	'/res/values/styles.xml'
]

def can_skip(file):
	for prefix in SKIP_FILES:
		if file.startswith(prefix):
			return True
	return False

def run_tests(apk, rz, u, rzh, au):
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
