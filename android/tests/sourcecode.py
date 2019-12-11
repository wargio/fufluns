import glob
import os

DESCRIPTION = "With the full or partial source code of the application, becomes easier to do reverse engineering"
SEVERITY    = 2

def find_src(apk, extension):
	files = glob.glob(os.path.join(apk.unzip, "**", extension), recursive=True)
	for file in files:
		apk.srccode.add(file[len(apk.unzip):])
	return len(files)


def run_tests(apk, r2, u, r2h, au):
	## Java
	nfiles = find_src(apk, "*.java")
	## Kotlin
	nfiles += find_src(apk, "*.kt")
	nfiles += find_src(apk, "*.kts")
	nfiles += find_src(apk, "*.ktm")
	msg = "not found."
	if nfiles > 0:
		msg = "found ({} files).".format(nfiles)
	u.test(apk, nfiles < 1, "Source Code files {}".format(msg), DESCRIPTION, SEVERITY)


def name_test():
	return "Detecting source code in the APK"