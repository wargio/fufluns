import glob
import os
import plistlib

def run_tests(ipa, r2, u, r2h):
	tmp = [f for f in glob.glob(os.path.join(ipa.directory, "Payload", "*", "Info.plist"), recursive=True)]
	plist = {}
	if len(tmp) > 0:
		plist = plistlib.readPlist(tmp[0])

	tmp = u.dk(plist, "NSAppTransportSecurity.NSExceptionDomains", {})
	for domain in tmp.keys():
		## AllowsInsecureHTTPLoads
		b = not u.dk(tmp[domain], "NSExceptionAllowsInsecureHTTPLoads")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} insecure HTTP loads connections on {1}".format("disallows" if b else "allows", domain), "MISSING", 5)
		b = not u.dk(tmp[domain], "NSThirdPartyExceptionAllowsInsecureHTTPLoads")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} third party insecure HTTP loads connections on {1}".format("disallows" if b else "allows", domain), "MISSING", 5)

		## RequiresForwardSecrecy
		b = u.dk(tmp[domain], "NSExceptionRequiresForwardSecrecy")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} forward secrecy on {1}".format("requires" if b else "does not require", domain), "MISSING", 5)
		b = u.dk(tmp[domain], "NSThirdPartyExceptionRequiresForwardSecrecy")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} forward secrecy on {1}".format("requires" if b else "does not require", domain), "MISSING", 5)

		## TLS Version
		tls = u.dk(tmp[domain], "NSExceptionMinimumTLSVersion")
		if tls is not None:
			u.test(ipa, tls not in ['TLSv1.0', 'TLSv1.1'], "App Transport Security (ATS) sets minimum TLS version is {0} on {1}".format(tls, domain), "MISSING", 5)
		tls = u.dk(tmp[domain], "NSThirdPartyExceptionMinimumTLSVersion")
		if tls is not None:
			u.test(ipa, tls not in ['TLSv1.0', 'TLSv1.1'], "App Transport Security (ATS) sets minimum TLS version is {0} on {1}".format(tls, domain), "MISSING", 5)

def name_test():
	return "Detection App Transport Security (ATS) "