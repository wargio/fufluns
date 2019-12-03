import json
import utils
import os

def sanitize(v):
	if isinstance(v, (bytes, bytearray)):
		return v.decode('utf-8', errors="ignore")
	return v

def cmdj(r2, cmd):
	v = sanitize(r2.cmd(cmd))
	return json.loads(v.replace('\\x', '\\u00'))

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
	return os.path.basename(utils.dk(cmdj(r2, 'ij'), "core.file", "(null)"))