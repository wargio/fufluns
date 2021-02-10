## fufluns - Copyright 2019-2021 - deroad

import re
import tldhelper

RE_HTTP = r"https?://(\d{1-3}\.\d{1-3}\.\d{1-3}\.\d{1-3}|[\w_\.-]+)(:[\d]+)?(/[\w_\.-//]+)"
RE_IPV4 = r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
RE_IPV6 = r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"

## having a regex for FQDNs is a mess..
RE_FQDN = r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)"

class ContextNet(object):
	def __init__(self, o, utils, file):
		super(ContextNet, self).__init__()
		self.o     = o
		self.utils = utils
		self.file  = file
		self._http = []
		self._fqdn = []
		self._ipv4 = []
		self._ipv6 = []

	def http(self, offset, value):
		self._http.append([self.file, offset, value])

	def fqdn(self, offset, value):
		self._fqdn.append([self.file, offset, value])

	def ipv4(self, offset, value):
		self._ipv4.append([self.file, offset, value])

	def ipv6(self, offset, value):
		self._ipv6.append([self.file, offset, value])

	def add_strings(self):
		for x in self._http:
			self.o.strings.add(x[0], 'http[s]', x[1], x[2])
		for x in self._fqdn:
			self.o.strings.add(x[0], 'FQDN', x[1], x[2])
		for x in self._ipv4:
			self.o.strings.add(x[0], 'IPv4', x[1], x[2])
		for x in self._ipv6:
			self.o.strings.add(x[0], 'IPv6', x[1], x[2])

def find_net(offset, string, ctx):
	ustring = string.strip()
	if len(ustring) < 1:
		return None
	found = re.findall(RE_HTTP, ustring)
	if found is not None and len(found) > 0:
		ctx.http(offset, string)
		return None

	found = re.findall(RE_IPV4, ustring)
	if found is not None and len(found) > 0:
		ctx.ipv4(offset, string)
		return None

	found = re.findall(RE_IPV6, ustring)
	if found is not None and len(found) > 0:
		ctx.ipv6(offset, string)
		return None

	found = re.findall(RE_FQDN, ustring)
	if found is not None and len(found) > 0:
		for f in found:
			if tldhelper.is_valid(f[0][len(f[1]):]):
				ctx.fqdn(offset, string)
				break

	return None

def run_tests(ipa, pipe, u, rzh):
	ctx = ContextNet(ipa, u, rzh.filename(pipe))
	rzh.iterate_strings(pipe, find_net, ctx)
	ctx.add_strings()

def name_test():
	return "Detection of hardcoded http[s]/IPs/hostnames strings."