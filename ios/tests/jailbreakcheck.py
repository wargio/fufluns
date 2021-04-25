## fufluns - Copyright 2019-2021 - deroad

import glob
import os

DESCRIPTION = "Applications on a jailbroken device run as root outside of the iOS sandbox. This can allow applications to access sensitive data contained in other apps or install malicious software that compromise the user data."
SEVERITY    = 6.7

queryschemas = {
	'cydia',
	'undecimus',
	'sileo',
}

filesystem_strings = {
	"/Applications/Cydia.app",
	"/Applications/FakeCarrier.app",
	"/Applications/Icy.app",
	"/Applications/IntelliScreen.app",
	"/Applications/MxTube.app",
	"/Applications/RockApp.app",
	"/Applications/SBSettings.app",
	"/Applications/WinterBoard.app",
	"/Applications/blackra1n.app",
	"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
	"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
	"/Library/MobileSubstrate/MobileSubstrate.dylib",
	"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
	"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
	"/bin/bash",
	"/bin/sh",
	"/etc/apt",
	"/etc/ssh/sshd_config",
	"/private/var/lib/apt",
	"/private/var/lib/cydia",
	"/private/var/mobile/Library/SBSettings/Themes",
	"/private/var/stash",
	"/private/var/tmp/cydia.log",
	"/usr/bin/sshd",
	"/usr/libexec/sftp-server",
	"/usr/libexec/ssh-keysign",
	"/usr/sbin/sshd",
	"/var/cache/apt",
	"/var/lib/apt",
	"/var/lib/cydia",
	"/usr/sbin/frida-server",
	"/usr/bin/cycript",
	"/usr/local/bin/cycript",
	"/usr/lib/libcycript.dylib",
}

def find_fs(offset, string, ctx):
	ustring = string.strip().upper()
	for key in filesystem_strings:
		if key.upper() in ustring:
			ctx.append(key)
	return None

def has_permission(ipa, plist, u, permission, description):
	p = u.dk(plist, permission, description)
	if len(p) > 0:
		u.permission(ipa, permission, description)

def run_tests(ipa, pipe, u, rzh):
	tmp = [f for f in glob.glob(os.path.join(ipa.directory, "Payload", "*", "Info.plist"), recursive=True)]
	plist = {}
	if len(tmp) > 0:
		plist = u.load_plist(tmp[0])

	tmp = u.dk(plist, "LSApplicationQueriesSchemes", [])
	schema_found = []
	filesystem_found = []

	if len(tmp) > 0:
		ipa.logger.notify("Schema[s] found: {}".format('://,'.join(tmp) + '://'))

	for schema in tmp:
		if schema in queryschemas:
			schema_found.append(schema + "://")

	rzh.iterate_strings(pipe, find_fs, filesystem_found)

	message = "Jailbreak/Root check is missing"
	if len(schema_found) and len(filesystem_found):
		message = "Jailbreak/Root check found via schemas (found {}) and filesystem paths (found {})".format(len(schema_found), len(filesystem_found))
	elif len(schema_found) > 0:
		message = "Jailbreak/Root check found via schemas {}".format(", ".join(schema_found))
	elif len(filesystem_found) > 0:
		message = "Jailbreak/Root check found via filesystem paths {}".format(", ".join(filesystem_found))

	u.test(ipa, len(schema_found) > 0 or len(filesystem_found) > 0, message, DESCRIPTION, SEVERITY)

def name_test():
	return "Detection Jailbreak/Root"