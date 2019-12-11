
DESCRIPTION = "If attacker-supplied strings are concatenated to a SQL query, SQL injection on a sqlite database may occur. This might leak sensitive information from the database or inject malicious payloads."
SEVERITY    = 8.4

class ContextSQL(object):
	def __init__(self, apk, utils):
		super(ContextSQL, self).__init__()
		self.apk   = apk
		self.utils = utils
		self.file  = ''
		self.found = []

	def add(self, offset, value):
		if value not in self.found:
			self.found.append(value)
			self.apk.strings.add(self.file, "SQLi", offset, value)

	def size(self):
		return len(self.found)

	def has_sqli(self):
		return self.size() > 0

def find_sql_injection(offset, string, ctx):
	ustring = string.strip().upper()
	## everything is uppercase, so we are looking for %s as %S
	if "%S" not in ustring:
		return None
	for prefix in ["INSERT ", "SELECT ", "ALTER ", "CREATE ", "DROP "]:
		if ustring.startswith(prefix):
			ctx.add(offset, string)
	return None

def run_tests(apk, pipes, u, r2h, au):
	ctx = ContextSQL(apk, u)
	for r2 in pipes:
		ctx.file = r2h.filename(r2)
		r2h.iterate_strings(r2, find_sql_injection, ctx)
	u.test(apk, not ctx.has_sqli(), "Common SQL Injection (found {} sqli)".format(ctx.size()), DESCRIPTION, SEVERITY)

def name_test():
	return "Detection SQL Injection"