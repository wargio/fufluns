import glob
import os
import plistlib

SEVERITY="severity"
DESCRIPTION="description"

DESC_ALLOWSINSECUREHTTPLOADS = "The application is allowed to send plain text HTTP traffic to the domain associated to this rule."
SVRT_ALLOWSINSECUREHTTPLOADS = 8.2
DESC_REQUIRESFORWARDSECRECY  = "Forward secrecy is a feature of specific key agreement protocols that gives assurances that session keys will not be compromised even if the private key of the server is compromised in the future."
SVRT_REQUIRESFORWARDSECRECY  = 4.7
DESC_MINIMUMTLSVERSION       = "It is suggested to enforce the usage of TLS 1.2 due the well known vulnerabilities in versions 1.0 and 1.1."
SVRT_MINIMUMTLSVERSION       = 6.1


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
			u.test(ipa, b, "App Transport Security (ATS) {0} insecure HTTP loads connections on {1}".format("disallows" if b else "allows", domain), DESC_ALLOWSINSECUREHTTPLOADS, SVRT_ALLOWSINSECUREHTTPLOADS)
		b = not u.dk(tmp[domain], "NSThirdPartyExceptionAllowsInsecureHTTPLoads")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} third party insecure HTTP loads connections on {1}".format("disallows" if b else "allows", domain), DESC_ALLOWSINSECUREHTTPLOADS, SVRT_ALLOWSINSECUREHTTPLOADS)

		## RequiresForwardSecrecy
		b = u.dk(tmp[domain], "NSExceptionRequiresForwardSecrecy")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} forward secrecy on {1}".format("requires" if b else "does not require", domain), DESC_REQUIRESFORWARDSECRECY, SVRT_REQUIRESFORWARDSECRECY)
		b = u.dk(tmp[domain], "NSThirdPartyExceptionRequiresForwardSecrecy")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} forward secrecy on {1}".format("requires" if b else "does not require", domain), DESC_REQUIRESFORWARDSECRECY, SVRT_REQUIRESFORWARDSECRECY)

		## TLS Version
		tls = u.dk(tmp[domain], "NSExceptionMinimumTLSVersion")
		if tls is not None:
			u.test(ipa, tls not in ['TLSv1.0', 'TLSv1.1'], "App Transport Security (ATS) sets minimum TLS version is {0} on {1}".format(tls, domain), DESC_MINIMUMTLSVERSION, SVRT_MINIMUMTLSVERSION)
		tls = u.dk(tmp[domain], "NSThirdPartyExceptionMinimumTLSVersion")
		if tls is not None:
			u.test(ipa, tls not in ['TLSv1.0', 'TLSv1.1'], "App Transport Security (ATS) sets minimum TLS version is {0} on {1}".format(tls, domain), DESC_MINIMUMTLSVERSION, SVRT_MINIMUMTLSVERSION)

def name_test():
	return "Detection App Transport Security (ATS)"