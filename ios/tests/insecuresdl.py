DESCRIPTION = "Insecure Standard C Library functions allows an attacker to exploit common buffer related vulnerabilities."
SEVERITY    = 6.4

insecure_std = [
	'gets',
	'getwd',
	'memcmp',
	'memcpy',
	'memmove',
	'me​mset',
	'scanf',
	'snprintf',
	'sprintf​',
	'sscanf',
	'stpcpy',
	'stpncpy',
	'strcat',
	'strcpy',
	'strlen',
	'strncat',
	'strncpy',
	'strtok',
	'strtok_r',
	'swprintf',
	'swscanf',
	'vscanf',
	'vsnprintf',
	'vsprintf',
	'vsscanf',
	'vswprintf',
	'wcpcpy',
	'wcpncpy',
	'wcrtomb',
	'wcscat',
	'wcscpy',
	'wcslen',
	'wcsncat',
	'wcsncpy',
	'wcsnrtombs',
	'wcsrtombs',
	'wcstok',
	'wcstombs',
	'wctomb',
	'wmemcmp',
	'wmemcpy',
	'wmemmove',
	'wmemset',
	'wscanf',
	'​alloca',
	'​realpath',
]

def run_tests(ipa, r2, u, r2h):
	found = []
	data = r2h.cmdj(r2, "iij")
	for e in data:
		v = u.dk(e, "name", "")
		if len(v) > 0 and v in insecure_std:
			found.append(v)
	result = ""
	if len(found) > 0:
		result = " ({})".format(", ".join(found))
	u.test(ipa, len(found) < 1, "Insecure Standard C Library functions imports" + result, DESCRIPTION, SEVERITY)

def name_test():
	return "Detection Insecure Standard C Library"