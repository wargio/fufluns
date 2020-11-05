## fufluns - Copyright 2020 - deroad

import glob
import os
import plistlib

SEVERITY="severity"
DESCRIPTION="description"

ISSU_NSURLSWIZZLING = "TrustKit swizzling on NSURL is disabled"
DESC_NSURLSWIZZLING = "Swizzling allows enabling pinning within an App without having to find every instance of NSURLConnection or NSURLSession delegates (best practice from docs)."
SVRT_NSURLSWIZZLING = 4.2

ISSU_NODOMAINS = "TrustKit No Pinned Domains"
DESC_NODOMAINS = "There are no pinned domains in the TrustKit configuration (maybe they are hardcoded in the code)."
SVRT_NODOMAINS = 8.2

ISSU_NOSUBDOMS = "TrustKit Pinning is not applied to subdomains on {}"
DESC_NOSUBDOMS = "TrustKit will not check pinning for all the subdomains of the specified domain."
SVRT_NOSUBDOMS = 4.3

ISSU_NOENFORCE = "TrustKit Pinning is not enforced on {}"
DESC_NOENFORCE = "TrustKit will not block SSL connections that caused a pin or certificate validation error."
SVRT_NOENFORCE = 8.2

ISSU_NOKEYHASHES = "TrustKit Public Key Hashes missing on {}"
DESC_NOKEYHASHES = "TrustKit will not be able to verify the certificate chain received from the server."
SVRT_NOKEYHASHES = 8.2

ISSU_NOBACKUPKEY = "TrustKit No Backup Public Key Hash on {}"
DESC_NOBACKUPKEY = "TrustKit documentation suggests to always provide at least one backup pin to prevent accidental blocking."
SVRT_NOBACKUPKEY = 8.2


def run_tests(ipa, r2, u, r2h):
	tmp = [f for f in glob.glob(os.path.join(ipa.directory, "Payload", "*", "Info.plist"), recursive=True)]
	plist = {}
	if len(tmp) > 0:
		plist = plistlib.readPlist(tmp[0])

	if u.dk(plist, "TSKConfiguration", None) == None:
		ipa.logger.notify("TrustKit not found")
		return

	## Allows Arbitrary Loads
	b = u.dk(plist, "TSKConfiguration.TSKSwizzleNetworkDelegates")
	if b is not None:
		u.test(ipa, not b, ISSU_NSURLSWIZZLING, DESC_NSURLSWIZZLING, SVRT_NSURLSWIZZLING)

	domains = u.dk(plist, "TSKConfiguration.TSKPinnedDomains", {})
	if len(domains.keys()) < 1:
		u.test(ipa, False, ISSU_NODOMAINS, DESC_NODOMAINS, SVRT_NODOMAINS)
		return

	for domain in domains:
		config = domains[domain]
		b = u.dk(config, "TSKIncludeSubdomains", False)
		u.test(ipa, b, ISSU_NOSUBDOMS.format(domain), DESC_NOSUBDOMS, SVRT_NOSUBDOMS)

		b = u.dk(config, "TSKEnforcePinning", True)
		u.test(ipa, b, ISSU_NOENFORCE.format(domain), DESC_NOENFORCE, SVRT_NOENFORCE)

		a = u.dk(config, "TSKPublicKeyHashes", [])
		if len(a) < 1:
			u.test(ipa, False, ISSU_NOKEYHASHES.format(domain), DESC_NOKEYHASHES, SVRT_NOKEYHASHES)
		elif len(a) < 2:
			u.test(ipa, False, ISSU_NOBACKUPKEY.format(domain), DESC_NOBACKUPKEY, SVRT_NOBACKUPKEY)



def name_test():
	return "Detection TrustKit (Certificate Pinning)"