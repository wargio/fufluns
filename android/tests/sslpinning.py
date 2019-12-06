import glob
import os

DESCRIPTION = "SSL Certificate Pinning allows the developer to specify a cryptographic identity that should be accepted by the application visiting some domains"
SEVERITY    = 8.2

PINNING_SIGNATURES = [
	'md5',
	'sha1',
	'sha224',
	'sha256',
	'sha384',
	'sha512'
]

class ContextStrings(object):
	def __init__(self, apk, utils):
		super(ContextStrings, self).__init__()
		self.apk    = apk
		self.utils  = utils
		self.file   = ''
		self.found  = []

	def add(self, offset, value):
		if offset not in self.found:
			self.found.append(offset)
			self.apk.strings.add(self.file, "CertPin", offset, value)

	def size(self):
		return len(self.found)

def find_strings(offset, string, ctx):
	ustring = string.strip()
	for key in PINNING_SIGNATURES:
		key += "/"
		if key in ustring and ustring.indexof(key) < 3 and len(ustring) > (len(key) + 3):
			ctx.add(offset, string)
			break
	return None

def run_tests(apk, pipes, u, r2h):
	ctx = ContextStrings(apk, u)
	for r2 in pipes:
		ctx.file = r2h.filename(r2)
		r2h.iterate_strings(r2, find_strings, ctx)

	files = glob.glob(os.path.join(apk.unzip, "**", "*.json"), recursive=True)
	for file in files:
		with open(file, "r") as fp:
			for line in fp.readlines():
				line = line.strip()
				if len(line) < 1:
					continue
				size = ctx.size()
				for key in PINNING_SIGNATURES:
					if key in line:
						ctx.found.append(file)
						break
				if size < ctx.size():
					break

	msg = "not found." if ctx.size() > 0 else "is available (found {} signatures).".format(ctx.size())
	u.test(apk, ctx.size() > 0, "SSL Pinning {}".format(msg), DESCRIPTION, SEVERITY)

def name_test():
	return "Detection of ssl pinning certificate signatures"