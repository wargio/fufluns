## fufluns - Copyright 2019 - deroad

import glob
import os

DESCRIPTION = "With the full or partial source code of the application, becomes easier to do reverse engineering"
SEVERITY    = 2

def find_src(ipa, extension):
	files = glob.glob(os.path.join(ipa.directory, "**", extension), recursive=True)
	for file in files:
		ipa.srccode.add(file[len(ipa.directory):])
	return len(files)


def run_tests(ipa, r2, u, r2h):
	## C/C++/Obj-C
	nfiles = find_src(ipa, "*.m")
	nfiles += find_src(ipa, "*.h")
	nfiles += find_src(ipa, "*.c")
	nfiles += find_src(ipa, "*.cpp")
	nfiles += find_src(ipa, "*.cxx")

	## Swift
	nfiles += find_src(ipa, "*.swift")

	## XCode
	nfiles += find_src(ipa, "*.pbxproj")
	nfiles += find_src(ipa, "*.xcworkspacedata")

	msg = "not found."
	if nfiles > 0:
		msg = "found ({} files).".format(nfiles)
	u.test(ipa, nfiles < 1, "Source Code files {}".format(msg), DESCRIPTION, SEVERITY)


def name_test():
	return "Detecting source code in the IPA"