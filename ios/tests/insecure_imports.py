## fufluns - Copyright 2019 - deroad

STD_ISSUE       = "Insecure Standard C Library functions imports"
STD_DESCRIPTION = "Insecure Standard C Library functions allows an attacker to exploit common buffer related vulnerabilities."
STD_SEVERITY    = 6.4

MALLOC_ISSUE       = "Usage of malloc may result in undefined behaviour."
MALLOC_DESCRIPTION = "The usage of malloc may generate undefined behaviour since the allocated buffer is not initialized."
MALLOC_SEVERITY    = 2.0

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
	malloc = False
	data = r2h.cmdj(r2, "iij")
	for e in data:
		v = u.dk(e, "name", "")
		if len(v) > 0:
			if v in insecure_std:
				found.append(v)
			elif v == "malloc":
				malloc = True
	result = ""
	if len(found) > 0:
		result = " ({})".format(", ".join(found))
	u.test(ipa, len(found) < 1, STD_ISSUE + result, STD_DESCRIPTION, STD_SEVERITY)
	u.test(ipa, not malloc, MALLOC_ISSUE, MALLOC_DESCRIPTION, MALLOC_SEVERITY)


def name_test():
	return "Detection Insecure Imports"