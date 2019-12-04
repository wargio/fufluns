DESCRIPTION = "MISSING"

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
	def __init__(self, apk, utils):
		super(ContextStrings, self).__init__()
		self.apk    = apk
		self.utils  = utils
		self.file   = ''
		self.found  = []

	def add(self, offset, value):
		if value not in self.found:
			self.found.append(value)
			self.apk.strings.add(self.file, "String", offset, value)

	def size(self):
		return len(self.found)

	def add_tests(self):
		if self.size() > 0:
			self.utils.test(self.apk, False, "Found some interesting strings ({} hit[s])".format(self.size()), DESCRIPTION, 8)
		else:
			self.apk.logger.info("[OK] No interesting strings signatures found")

def find_secrets(offset, string, ctx):
	ustring = string.strip()
	for key in STRINGS_SIGNATURES:
		if key in ustring:
			ctx.add(offset, string)
	return None

def run_tests(apk, pipes, u, r2h):
	ctx = ContextStrings(apk, u)
	for r2 in pipes:
		ctx.file = r2h.filename(r2)
		r2h.iterate_strings(r2, find_secrets, ctx)
	ctx.add_tests()

def name_test():
	return "Detection of interesting string signatures"