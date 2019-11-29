
DESCRIPTION = "If attacker-supplied strings are concatenated to a SQL query, SQL injection on a sqlite database may occur. This might leak sensitive information from the database or inject malicious payloads."

class ContextSQL(object):
	def __init__(self, apk, utils):
		super(ContextSQL, self).__init__()
		self.apk   = apk
		self.utils = utils
		self.found = []

	def add(self, value):
		if value not in self.found:
			self.found.append(value)

	def size(self):
		return len(self.found)

	def has_sqli(self):
		return self.size() > 0


def find_sql_injection(string, ctx):
	string = string.strip().upper()
	## everything is uppercase, so we are looking for %s as %S
	if "%S" not in string:
		return None
	for prefix in ["INSERT", "SELECT", "ALTER", "CREATE", "DROP"]:
		if string.startswith(prefix):
			ctx.add(string)
	return None

def run_tests(apk, pipes, u, r2h):
	ctx = ContextSQL(apk, u)
	for r2 in pipes:
		r2h.iterate_strings(r2, find_sql_injection, ctx)
	u.test(apk, not ctx.has_sqli(), "Common SQL Injection (found {} sqli)".format(ctx.size()), DESCRIPTION, 8)

def name_test():
	return "Detection SQL Injection"