## fufluns - Copyright 2019-2021 - deroad

DESCRIPTION = "If attacker-supplied strings are concatenated to a SQL query, SQL injection on a sqlite database may occur. This might leak sensitive information from the database or inject malicious payloads."
SEVERITY    = 8.4

class ContextSQL(object):
	def __init__(self, ipa, utils, file):
		super(ContextSQL, self).__init__()
		self.ipa   = ipa
		self.utils = utils
		self.file  = file
		self.found = []

	def add(self, offset, value):
		if value not in self.found:
			self.found.append(value)
			self.ipa.strings.add(self.file, "SQLi", offset, value)

	def size(self):
		return len(self.found)

	def has_sqli(self):
		return self.size() > 0

def find_sql_injection(offset, string, ctx):
	ustring = string.strip().upper()
	if "%@" not in ustring and "%S" not in ustring:
		return None
	for prefix in ["INSERT ", "SELECT ", "ALTER ", "CREATE ", "DROP "]:
		if ustring.startswith(prefix):
			ctx.add(offset, string.strip())
	return None

def run_tests(ipa, pipe, u, rzh):
	ctx = ContextSQL(ipa, u, rzh.filename(pipe))
	rzh.iterate_strings(pipe, find_sql_injection, ctx)
	u.test(ipa, not ctx.has_sqli(), "Common SQL Injection (found {} sqli)".format(ctx.size()), DESCRIPTION, SEVERITY)

def name_test():
	return "Detection SQL Injection"