## fufluns - Copyright 2019,2020 - deroad

import json
import utils
import os
import re

def sanitize(v):
	if isinstance(v, (bytes, bytearray)):
		return v.decode('utf-8', errors="ignore")
	return v

def encode_json(x):
	x = json.dumps(x)
	return x[1:][:-1]

def needs_encoding(x):
	return x > 31 and x < 127

def sanitize_json(v):
	v = sanitize(v).strip()
	v = v.replace('\\x', '\\u00')
	v = v.replace(', "', ',"')
	v = ''.join([i if needs_encoding(ord(i)) else encode_json(i) for i in v])
	v = re.sub(r'(([^\[\{:,\\])\"([^:,\]\}]))', '\\2\\"\\3', v)
	return v

def cmdj(r2, cmd):
	v = sanitize_json(r2.cmd(cmd))
	return json.loads(v, strict=False)

def cmd(r2, cmd):
	return sanitize(r2.cmd(cmd))

def has_info(r2, key):
	data = cmdj(r2, "iIj")
	return utils.dk(data, key, False)

def has_import(r2, values):
	data = cmdj(r2, "iij")
	for e in data:
		v = utils.dk(e, "name", "")
		if len(v) > 0 and v in values:
			return True
	return False

def iterate_strings(r2, func, usr_data=None):
	data = cmdj(r2, "izzj")
	for e in data:
		v = utils.dk(e, "string", "")
		o = utils.dk(e, "paddr", 0)
		if len(v) > 0:
			x = func(o, v, usr_data)
			if x is not None:
				return

def filename(r2):
	return os.path.basename(cmd(r2, 'ij~{core.file}'))