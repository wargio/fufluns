DESCRIPTION = "Applications on a 'rooted' device can run as root outside of the kernel sandbox. This can allow applications to access sensitive data contained in other apps or install malicious software that compromise the user data."
SEVERITY    = 6.7

ROOT_PACKAGES = [
	"com.noshufou.android.su",
	"com.noshufou.android.su.elite",
	"eu.chainfire.supersu",
	"com.koushikdutta.superuser",
	"com.thirdparty.superuser",
	"com.yellowes.su",
	"com.koushikdutta.rommanager",
	"com.koushikdutta.rommanager.license",
	"com.dimonvideo.luckypatcher",
	"com.chelpus.lackypatch",
	"com.ramdroid.appquarantine",
	"com.ramdroid.appquarantinepro",
	"com.devadvance.rootcloak",
	"com.devadvance.rootcloakplus",
	"de.robv.android.xposed.installer",
	"com.saurik.substrate",
	"com.zachspong.temprootremovejb",
	"com.amphoras.hidemyroot",
	"com.amphoras.hidemyrootadfree",
	"com.formyhm.hiderootPremium",
	"com.formyhm.hideroot",
	"me.phh.superuser",
	"eu.chainfire.supersu.pro",
	"com.kingouser.com"
];

ROOT_BINARIES = [
	"busybox",
	"supersu",
	"Superuser.apk",
	"KingoUser.apk",
	"SuperSu.apk"
];

ROOT_PROPERTIES = [
	"ro.build.selinux",
	"ro.debuggable",
	"service.adb.root",
	"ro.secure"
];

def run_tests(apk, pipes, u, r2h, au):
	found = []
	idx = 1
	for r2 in pipes:
		##apk.logger.notify("analyzing pipe {} of {}.".format(idx, len(pipes)))
		idx += 1
		data = r2h.cmdj(r2, "izj")
		for e in data:
			skip = False
			v = u.dk(e, "string", "").strip()
			if len(v) < 1:
				continue
			if len(v) < 3:
				## skipping any string that is less than 3
				## avoids false positives on "su"
				continue
			if v.endswith("/su"):
				found.append(v)
				continue

			for s in ROOT_PACKAGES:
				if s in v:
					found.append(v)
					skip = True
					break
			if skip:
				continue
			for s in ROOT_BINARIES:
				if s in v:
					found.append(v)
					skip = True
					break
			if skip:
				continue
			for s in ROOT_PROPERTIES:
				if s in v:
					found.append(v)
					break
	result = "not found"
	if len(found) > 0:
		result = "found ({})".format(", ".join(found))
	u.test(apk, len(found) > 0, "Root detection " + result, DESCRIPTION, SEVERITY)

def name_test():
	return "Root detection"
