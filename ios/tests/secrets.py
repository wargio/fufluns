## fufluns - Copyright 2019-2021 - deroad

DESCRIPTION = "Easily discoverable of Private Key embedded inside the application"
SEVERITY    = 8.4

SECRETS_SIGNATURES = {
	"RSA Private Key":     "-----BEGIN RSA PRIVATE KEY-----",
	"OPENSSH Private Key": "-----BEGIN OPENSSH PRIVATE KEY-----",
	"DSA Private Key":     "-----BEGIN DSA PRIVATE KEY-----",
	"EC Private Key":      "-----BEGIN EC PRIVATE KEY-----",
	"PGP Private Key":     "-----BEGIN PGP PRIVATE KEY BLOCK-----",
	"AWS Key":             "AKIA",
}

class ContextSecrets(object):
	def __init__(self, ipa, utils, file):
		super(ContextSecrets, self).__init__()
		self.ipa   = ipa
		self.utils = utils
		self.file  = file
		self.found = {}

	def add(self, key, offset, value):
		if key not in self.found:
			self.found[key] = []
		if value not in self.found[key]:
			self.found[key].append(value)
			self.ipa.strings.add(self.file, "Secret", offset, value)

	def size(self, key):
		return len(self.found)

	def add_tests(self):
		for key in self.found:
			self.utils.test(self.ipa, False, "Found {} ({} hit[s])".format(key, self.size(key)), DESCRIPTION, SEVERITY)
		if len(self.found) < 1:
			self.ipa.logger.info("[OK] No secrets signatures found")

def find_secrets(offset, string, ctx):
	ustring = string.strip()
	if "%s" not in ustring:
		return None
	for key in SECRETS_SIGNATURES:
		prefix = SECRETS_SIGNATURES[key]
		if prefix in ustring:
			ctx.add(key, offset, string)
	return None

def run_tests(ipa, pipe, u, rzh):
	ctx = ContextSecrets(ipa, u, rzh.filename(pipe))
	rzh.iterate_strings(pipe, find_secrets, ctx)
	ctx.add_tests()

def name_test():
	return "Detection of secrets signatures"