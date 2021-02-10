## fufluns - Copyright 2019-2021 - deroad

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

def cmdj(pipe, cmd):
	v = sanitize_json(pipe.cmd(cmd))
	return json.loads(v, strict=False)

def cmd(pipe, cmd):
	return sanitize(pipe.cmd(cmd))

def has_info(pipe, key):
	data = cmdj(pipe, "iIj")
	return utils.dk(data, key, False)

def has_import(pipe, values):
	data = cmdj(pipe, "iij")
	for e in data:
		v = utils.dk(e, "name", "")
		if len(v) > 0 and v in values:
			return True
	return False

def iterate_strings(pipe, func, usr_data=None):
	data = cmdj(pipe, "izzj")
	for e in data:
		v = utils.dk(e, "string", "")
		o = utils.dk(e, "paddr", 0)
		if len(v) > 0:
			x = func(o, v, usr_data)
			if x is not None:
				return

def filename(pipe):
	return os.path.basename(utils.dk(cmdj(pipe, 'ij'), "core.file", "(null)"))