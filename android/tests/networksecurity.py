## fufluns - Copyright 2019 - deroad

import glob
import os

NSC_ISSUE = "The Android network security configuration {}."
NSC_DESCR = "The Android network security configuration feature lets apps customize their network security settings in a safe, declarative configuration file without modifying app code"
NSC_SEVER = 8.2

NSC_ISSUE_CLEARTEXT = "The Android network security configuration {}."
NSC_DESCR_CLEARTEXT = "The Android application has one or more domains that allows the usage of requests that do not require TLS connection (file {})."
NSC_SEVER_CLEARTEXT = 8.2

SSL_DESCRIPTION = "SSL Certificate Pinning allows the developer to specify a cryptographic identity that should be accepted by the application visiting some domains"
SSL_SEVERITY    = 8.2

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
		if key in ustring and ustring.index(key) < 3 and len(ustring) > (len(key) + 3):
			ctx.add(offset, string)
			break
	return None

def run_tests(apk, pipes, u, r2h, au):
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


	nscfile = au.NetworkSecurityConfig.find(apk.apktool)
	u.test(apk, nscfile is not None, NSC_ISSUE.format("was found" if nscfile is not None else "was not found"), NSC_DESCR, NSC_SEVER)
	if nscfile is not None:
		nsc = au.NetworkSecurityConfig(nscfile)
		ctx.found.extend(nsc.pins())
		ctx.found.extend(nsc.certificates())
		cleartext = nsc.cleartext()
		msg = NSC_ISSUE_CLEARTEXT.format("doesn't allow plaintext traffic")
		if len(cleartext) > 0:
			msg = NSC_ISSUE_CLEARTEXT.format("allows plaintext traffic on domains: {}".format(", ".join(cleartext)))
		u.test(apk, len(cleartext) < 1, msg, NSC_DESCR_CLEARTEXT.format(nscfile[len(apk.apktool):]), NSC_SEVER_CLEARTEXT)

	msg = "not found."
	if ctx.size() > 0:
		msg = "is available (found {} signatures/pins/certificates).".format(ctx.size())
	u.test(apk, ctx.size() > 0, "SSL Pinning {}".format(msg), SSL_DESCRIPTION, SSL_SEVERITY)


def name_test():
	return "Detection Android Network Security Config and SSL pinning certificate signatures"
