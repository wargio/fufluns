## fufluns - Copyright 2019-2020 - deroad

import re, base64

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

JAVA_REGEX = r'(L([a-zA-Z\d\/\$_\-]+)(([a-zA-Z\d\.<>\$]+)?(\(\)|\([\[a-zA-Z\d\/\$_\-;]+\))([\[a-zA-Z\d\/\$_\-;]+|[\[ZBSCIJFDV]))?)'
HEX_REGEX = r'^[A-Fa-f0-9]{5,}$'
BASE64_REGEX = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
BADB64_REGEX = r'^[A-Za-z$+]+$'

KNOWN_BADB64 = [
	'0123456789abcdef',
	'0123456789ABCDEF',
	'0123456789ABCDEFGHJKMNPQRSTVWXYZ',
	'0123456789ABCDEFGHIJKLMNOPQRSTUV',
	'0123456789ABCDEFGHIJKLMNOPQRSTUVZ',
	'0oO1iIlLAaBbCcDdEeFfGgHhJjKkMmNnPpQqRrSsTtVvWwXxYyZz',
	'ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567',
	'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567',
	'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
	'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
	'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
	'AES/CBC/NoPadding',
	'AES/CBC/PKCS5Padding',
	'AES/ECB/NoPadding',
	'AES/ECB/PKCS5Padding',
	'DES/CBC/NoPadding',
	'DES/CBC/PKCS5Padding',
	'DES/ECB/NoPadding',
	'DES/ECB/PKCS5Padding',
	'DESede/CBC/NoPadding',
	'DESede/CBC/PKCS5Padding',
	'DESede/ECB/NoPadding',
	'DESede/ECB/PKCS5Padding',
	'RSA/ECB/PKCS1Padding',
	'RSA/ECB/OAEPWithSHA-1AndMGF1Padding',
	'RSA/ECB/OAEPWithSHA-256AndMGF1Padding'
]

def is_hex(value):
	if value in KNOWN_BADB64:
		return False
	return re.match(HEX_REGEX, value, flags=re.M)

def is_base64(value):
	if value in KNOWN_BADB64:
		return False
	found = re.search(BASE64_REGEX, value, flags=re.M)
	if found and not re.match(BADB64_REGEX, value, flags=re.M):
		found = found.group(0)
		try:
			decoded = base64.b64decode(found.encode('ascii'))
			return len(decoded) > 0
		except Exception:
			pass
	return False

class ContextStrings(object):
	def __init__(self, apk, utils):
		super(ContextStrings, self).__init__()
		self.apk    = apk
		self.utils  = utils
		self.file   = ''
		self.found  = []

	def add(self, offset, value, stype="String"):
		if value not in self.found:
			self.found.append(value)
			self.apk.strings.add(self.file, stype, offset, value)

	def size(self):
		return len(self.found)

def find_strings(offset, string, ctx):
	if re.search(JAVA_REGEX, string, flags=re.M):
		return None

	if is_hex(string):
		ctx.add(offset, string, "hex")
		return None

	if len(string) > 4 and is_base64(string):
		ctx.add(offset, string, "base64")
		return None

	ustring = string.strip().upper()
	for key in STRINGS_SIGNATURES:
		if key.upper() in ustring:
			ctx.add(offset, string)
	return None

def run_tests(apk, pipes, u, r2h, au):
	ctx = ContextStrings(apk, u)
	for r2 in pipes:
		ctx.file = r2h.filename(r2)
		r2h.iterate_strings(r2, find_strings, ctx)
	if ctx.size() < 1:
		apk.logger.info("[OK] No interesting strings signatures found")

def name_test():
	return "Detection of interesting string signatures"