## fufluns - Copyright 2019-2021 - deroad

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

HEX_REGEX = r'^[A-Fa-f0-9]{5,}$'
BASE64_REGEX = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
BADB64_REGEX = r'^[A-Za-z$+]+$|^[A-Za-z/+]+$'

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
	'getInt32',
	'getInt64',
	'GPBInt32DoubleDictionary',
	'GPBInt32ObjectDictionary',
	'GPBInt32UInt32Dictionary',
	'GPBInt32UInt64Dictionary',
	'GPBInt64DoubleDictionary',
	'GPBInt64ObjectDictionary',
	'GPBInt64UInt32Dictionary',
	'GPBInt64UInt64Dictionary',
	'GPBStringInt32Dictionary',
	'GPBStringInt64Dictionary',
	'GPBUInt32FloatDictionary',
	'GPBUInt32Int32Dictionary',
	'GPBUInt32Int64Dictionary',
	'GPBUInt64FloatDictionary',
	'GPBUInt64Int32Dictionary',
	'GPBUInt64Int64Dictionary',
	'ISO8601DateFormatter',
	'readSFixed32',
	'readSFixed64',
	'St9exception',
	'SyntaxProto2',
	'SyntaxProto3',
	'TypeSfixed32',
	'TypeSfixed64',
	'gost2001',
	'gost94cc',
	'hmacWithSHA1',
	'md2WithRSAEncryption',
	'md4WithRSAEncryption',
	'md5WithRSAEncryption',
	'ripemd160WithRSA',
	'x500UniqueIdentifier',
	'h7BadExpectedAccessE',
	'0JSExecutorE',
	'11ColumnNoVecEEE',
	'4JSBigStdStringE',
	'6InstanceCallbackEEE',
	'6RowSumI',
	'8MessageQueueThreadE',
	'8RowNoVecEEE',
	'9BaseValueEE'
	'N2cv13BaseRowFilterE',
	'N2cv6RowSumIddEE',
	'N2cv6RowSumIfdEE',
	'N2cv6RowSumIhdEE',
	'N2cv6RowSumIhiEE',
	'N2cv6RowSumIiiEE',
	'N2cv6RowSumIsdEE',
	'N2cv6RowSumIsiEE',
	'N2cv6RowSumItdEE',
	'N2cv6RowSumItiEE',
	'N5folly22OptionalEmptyExceptionE',
	'N8facebook3jsi15InstrumentationE',
	'N8facebook5react17JSBigBufferStringE',
	'N8facebook5react17JSExecutorFactoryE',
	'N8facebook5react17JSModulesUnbundleE',
	'N8facebook5react17RAMBundleRegistryE',
]

class ContextStrings(object):
	def __init__(self, ipa, utils, file):
		super(ContextStrings, self).__init__()
		self.ipa    = ipa
		self.utils  = utils
		self.file   = file
		self.found  = []

	def add(self, offset, value, stype="String"):
		if value not in self.found:
			self.found.append(value)
			self.ipa.strings.add(self.file, stype, offset, value)

	def size(self):
		return len(self.found)

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

def find_strings(offset, string, ctx):
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

def run_tests(ipa, pipe, u, rzh):
	ctx = ContextStrings(ipa, u, rzh.filename(pipe))
	rzh.iterate_strings(pipe, find_strings, ctx)
	if ctx.size() < 1:
		ipa.logger.info("[OK] No interesting strings signatures found")

def name_test():
	return "Detection of interesting string signatures"
