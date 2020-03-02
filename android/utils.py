## fufluns - Copyright 2019 - deroad

import xml.etree.ElementTree as ET
import datetime
import time
import os

def _pt(s):
	if s is None:
		return 0
	utc_time = datetime.datetime.strptime(s, "%Y-%m-%d")
	return (utc_time - datetime.datetime(1970, 1, 1)).total_seconds()

def _na(node, key, default=None):
	if key in node.attrib:
		return node.attrib[key]
	return default

def _lm(f, l):
	return list(map(f, l))

class Domain(object):
	"""Domain object"""
	def __init__(self, node, subdomain=False):
		super(Domain, self).__init__()
		if isinstance(node, str):
			self.domainname = node
			self.subdomain = subdomain
		else:
			self.domainname = node.text
			self.subdomain = _na(node, 'includeSubdomains', subdomain)

class Pins(object):
	"""Pins object"""
	def __init__(self, node):
		super(Pins, self).__init__()
		self.expiration = _pt(_na(node, 'expiration', None))
		self.pins = _lm(lambda x: x.text, node.findall("pin"))

	def is_expired(self):
		if self.expiration == 0:
			return False
		return (self.expiration - time.time()) < 0

class DomConfig(object):
	"""Domains Configuration object"""
	def __init__(self, node):
		super(DomConfig, self).__init__()
		self.cleartext = _na(node, 'cleartextTrafficPermitted', False)
		self.domains = _lm(lambda x: Domain(x), node.findall("domain"))
		self.certificates = _lm(lambda x: _na(x, 'src', '??'), node.findall("trust-anchors/certificates"))
		self.pinset = _lm(lambda x: Pins(x), node.findall("pin-set"))

def _domain_configs(node, key):
	cfgs = _lm(lambda x: DomConfig(x), node.findall(key))
	if len(cfgs) < 1:
		return []
	cfgs.extend(_domain_configs(node, key + "/domain-config"))
	return cfgs

class NetworkSecurityConfig(object):
	"""Network Security Config object"""
	def find(folder):
		manifest = os.path.join(folder, "AndroidManifest.xml")
		root = ET.parse(manifest).getroot()
		application = root.findall("application")
		filename = None
		for elem in application:
			for att in elem.attrib:
				if att != "{http://schemas.android.com/apk/res/android}networkSecurityConfig":
					continue
				filename = elem.attrib[att]
		if filename is None:
			return None
		return os.path.join(folder, "res", filename[1:] + ".xml")

	def __init__(self, filename):
		super(NetworkSecurityConfig, self).__init__()
		root = ET.parse(filename).getroot()
		self.filename = filename
		self.base     = _domain_configs(root, "base-config")
		self.debug    = _domain_configs(root, "debug-overrides")
		self.configs  = _domain_configs(root, "domain-config")
		for c in self.base:
			if c.cleartext and len(c.domains) < 1:
				c.domains.append(Domain("any"))
		for c in self.debug:
			if c.cleartext and len(c.domains) < 1:
				c.domains.append(Domain("any"))

	def certificates(self):
		ce = []
		for c in self.debug:
			ce.extend(c.certificates)
		for c in self.base:
			ce.extend(c.certificates)
		for c in self.configs:
			ce.extend(c.certificates)
		return ce

	def pins(self):
		p = []
		for c in self.debug:
			for ps in c.pinset:
				p.extend(ps.pins)
		for c in self.base:
			for ps in c.pinset:
				p.extend(ps.pins)
		for c in self.configs:
			for ps in c.pinset:
				p.extend(ps.pins)
		return p

	def cleartext(self):
		d = []
		for c in self.debug:
			if c.cleartext:
				d.extend(_lm(lambda x: x.domainname, c.domains))
		for c in self.base:
			if c.cleartext:
				d.extend(_lm(lambda x: x.domainname, c.domains))
		for c in self.configs:
			if c.cleartext:
				d.extend(_lm(lambda x: x.domainname, c.domains))
		return d

	def expired(self):
		p = []
		for c in self.debug:
			for ps in c.pinset:
				if c.is_expired():
					p.extend(ps.pins)
		for c in self.base:
			for ps in c.pinset:
				if c.is_expired():
					p.extend(ps.pins)
		for c in self.configs:
			for ps in c.pinset:
				if c.is_expired():
					p.extend(ps.pins)
		return p