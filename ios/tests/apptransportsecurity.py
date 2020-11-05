## fufluns - Copyright 2019-2021 - deroad

import glob
import os

SEVERITY="severity"
DESCRIPTION="description"

ISSU_ALLOWSARBITRARYLOADS = "App Transport Security (ATS) restrictions are disabled on all domains"
DESC_ALLOWSARBITRARYLOADS = "The application has disabled all the security restrictions for all domains."
SVRT_ALLOWSARBITRARYLOADS = 8.2

ISSU_ALLOWSARBITRARYLOADSFORMEDIA = "App Transport Security (ATS) restrictions are disabled on all domains for media resources"
DESC_ALLOWSARBITRARYLOADSFORMEDIA = "The application has disabled all the security restrictions for all domains when loading media to HTTP resources."
SVRT_ALLOWSARBITRARYLOADSFORMEDIA = 8.2

ISSU_ALLOWSARBITRARYLOADSINWEBCONTENT = "App Transport Security (ATS) restrictions are disabled on all domains for web-views (WKWebView, UIWebView and WebView)"
DESC_ALLOWSARBITRARYLOADSINWEBCONTENT = "The application has disabled all the security restrictions for all domains when loading web views with links to HTTP resources."
SVRT_ALLOWSARBITRARYLOADSINWEBCONTENT = 8.2

DESC_ALLOWSINSECUREHTTPLOADS = "The application is allowed to send plain text HTTP traffic to the domain associated to this rule."
SVRT_ALLOWSINSECUREHTTPLOADS = 8.2

DESC_REQUIRESFORWARDSECRECY = "Forward secrecy is a feature of specific key agreement protocols that gives assurances that session keys will not be compromised even if the private key of the server is compromised in the future."
SVRT_REQUIRESFORWARDSECRECY = 4.7

DESC_MINIMUMTLSVERSION = "It is suggested to enforce the usage of TLS 1.2 due the well known vulnerabilities in versions 1.0 and 1.1."
SVRT_MINIMUMTLSVERSION = 6.1

ISSU_ALLOWSLOCALNETWORKING = "App Transport Security (ATS) restrictions are disabled on all private/local connections"
DESC_ALLOWSLOCALNETWORKING = "The application has disabled all the security restrictions for all private/local connections."
SVRT_ALLOWSLOCALNETWORKING = 8.2

def run_tests(ipa, pipe, u, rzh):
	tmp = [f for f in glob.glob(os.path.join(ipa.directory, "Payload", "*", "Info.plist"), recursive=True)]
	plist = {}
	if len(tmp) > 0:
		plist = u.load_plist(tmp[0])

	# check for TrustKit
	if u.dk(plist, "TSKConfiguration") != None:
		ipa.logger.notify("TrustKit was found, so App Transport Security config is ignored.")
		return

	tmp = u.dk(plist, "NSAppTransportSecurity.NSExceptionDomains", {})
	for domain in tmp.keys():
		domain_msg = domain
		if u.dk(tmp[domain], "NSIncludesSubdomains", False):
			domain_msg += " including subdomains"
		## AllowsInsecureHTTPLoads
		b = not u.dk(tmp[domain], "NSExceptionAllowsInsecureHTTPLoads")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} insecure HTTP loads connections on {1}".format("disallows" if b else "allows", domain_msg), DESC_ALLOWSINSECUREHTTPLOADS, SVRT_ALLOWSINSECUREHTTPLOADS)
		b = not u.dk(tmp[domain], "NSThirdPartyExceptionAllowsInsecureHTTPLoads")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} third party insecure HTTP loads connections on {1}".format("disallows" if b else "allows", domain_msg), DESC_ALLOWSINSECUREHTTPLOADS, SVRT_ALLOWSINSECUREHTTPLOADS)

		## RequiresForwardSecrecy
		b = u.dk(tmp[domain], "NSExceptionRequiresForwardSecrecy")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} forward secrecy on {1}".format("requires" if b else "does not require", domain_msg), DESC_REQUIRESFORWARDSECRECY, SVRT_REQUIRESFORWARDSECRECY)
		b = u.dk(tmp[domain], "NSThirdPartyExceptionRequiresForwardSecrecy")
		if b is not None:
			u.test(ipa, b, "App Transport Security (ATS) {0} forward secrecy on {1}".format("requires" if b else "does not require", domain_msg), DESC_REQUIRESFORWARDSECRECY, SVRT_REQUIRESFORWARDSECRECY)

		## TLS Version
		tls = u.dk(tmp[domain], "NSExceptionMinimumTLSVersion")
		if tls is not None:
			u.test(ipa, tls not in ['TLSv1.0', 'TLSv1.1'], "App Transport Security (ATS) sets minimum TLS version is {0} on {1}".format(tls, domain_msg), DESC_MINIMUMTLSVERSION, SVRT_MINIMUMTLSVERSION)
		tls = u.dk(tmp[domain], "NSThirdPartyExceptionMinimumTLSVersion")
		if tls is not None:
			u.test(ipa, tls not in ['TLSv1.0', 'TLSv1.1'], "App Transport Security (ATS) sets minimum TLS version is {0} on {1}".format(tls, domain_msg), DESC_MINIMUMTLSVERSION, SVRT_MINIMUMTLSVERSION)

	## Allows Arbitrary Loads
	b = u.dk(plist, "NSAppTransportSecurity.NSAllowsArbitraryLoads")
	if b is not None:
		u.test(ipa, not b, ISSU_ALLOWSARBITRARYLOADS, DESC_ALLOWSARBITRARYLOADS, SVRT_ALLOWSARBITRARYLOADS)

	## Allows Arbitrary Loads For Media
	b = u.dk(plist, "NSAppTransportSecurity.NSAllowsArbitraryLoadsForMedia")
	if b is not None:
		u.test(ipa, not b, ISSU_ALLOWSARBITRARYLOADSFORMEDIA, DESC_ALLOWSARBITRARYLOADSFORMEDIA, SVRT_ALLOWSARBITRARYLOADSFORMEDIA)

	## Allows Arbitrary Loads In Web Content
	b = u.dk(plist, "NSAppTransportSecurity.NSAllowsArbitraryLoadsInWebContent")
	if b is not None:
		u.test(ipa, not b, ISSU_ALLOWSARBITRARYLOADSINWEBCONTENT, DESC_ALLOWSARBITRARYLOADSINWEBCONTENT, SVRT_ALLOWSARBITRARYLOADSINWEBCONTENT)

	## Allows Arbitrary Loads In Local IP space
	b = u.dk(plist, "NSAppTransportSecurity.NSAllowsLocalNetworking")
	if b is not None:
		u.test(ipa, not b, ISSU_ALLOWSLOCALNETWORKING, DESC_ALLOWSLOCALNETWORKING, SVRT_ALLOWSLOCALNETWORKING)



def name_test():
	return "Detection App Transport Security (ATS)"