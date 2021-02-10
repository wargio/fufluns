## fufluns - Copyright 2019-2021 - deroad

MALLOC_ISSUE       = "Usage of malloc may result in undefined behaviour."
MALLOC_DESCRIPTION = "The usage of malloc may generate undefined behaviour since the allocated buffer is not initialized."
MALLOC_SEVERITY    = 2.0

STD_ISSUE       = "Insecure Standard C Library functions imports"
STD_DESCRIPTION = "Insecure Standard C Library functions allows an attacker to exploit common buffer related vulnerabilities."
STD_SEVERITY    = 6.4

RANDOM_ISSUE       = "Usage of non CSPRNG results in predictable values which may be used in security-sensitive context"
RANDOM_DESCRIPTION = "The usage of non cryptographically secure random number generators results in attacks that can derive functions able to reproduce the values of the PRNG."
RANDOM_SEVERITY    = 4.8

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

insecure_random = [
	"drand48",
	"erand48",
	"jrand48",
	"lcong48",
	"lrand48",
	"mrand48",
	"nrand48",
	"rand",
	"seed48",
	"srand",
	"srand48",
]

def run_tests(ipa, pipe, u, rzh):
	libc = []
	random = []
	malloc = False
	data = rzh.cmdj(pipe, "iij")
	for e in data:
		v = u.dk(e, "name", "")
		if len(v) > 0:
			if v in insecure_std:
				libc.append(v)
			elif v == "malloc":
				malloc = True
			elif v in insecure_random:
				random.append(v)

	u.test(ipa, not malloc, MALLOC_ISSUE, MALLOC_DESCRIPTION, MALLOC_SEVERITY)

	result = "."
	if len(libc) > 0:
		result = " ({}).".format(", ".join(libc))
	u.test(ipa, len(libc) < 1, STD_ISSUE + result, STD_DESCRIPTION, STD_SEVERITY)

	result = "."
	if len(random) > 0:
		result = " ({}).".format(", ".join(random))
	u.test(ipa, len(random) < 1, RANDOM_ISSUE + result, RANDOM_DESCRIPTION, RANDOM_SEVERITY)


def name_test():
	return "Detection Insecure Imports"