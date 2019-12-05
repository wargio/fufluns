STRINGS_SIGNATURES = [
	':"',
	': "',
	' oauth',
	' security',
	'oauth ',
	'security ',
	'security_token',
	'token',
	'passw',
	'proto',
	'debugger',
	'sha1',
	'sha256',
]

class ContextStrings(object):
	def __init__(self, ipa, utils, file):
		super(ContextStrings, self).__init__()
		self.ipa    = ipa
		self.utils  = utils
		self.file   = file
		self.found  = []

	def add(self, offset, value):
		if value not in self.found:
			self.found.append(value)
			self.ipa.strings.add(self.file, "String", offset, value)

	def size(self):
		return len(self.found)

def find_strings(offset, string, ctx):
	ustring = string.strip().upper()
	for key in STRINGS_SIGNATURES:
		if key.upper() in ustring:
			ctx.add(offset, string)
	return None

def run_tests(ipa, r2, u, r2h):
	ctx = ContextStrings(ipa, u, r2h.filename(r2))
	r2h.iterate_strings(r2, find_strings, ctx)
	if ctx.size() < 1:
		ipa.logger.info("[OK] No interesting strings signatures found")

def name_test():
	return "Detection of interesting string signatures"