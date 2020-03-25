## fufluns - Copyright 2019 - deroad

def is_decrypted(r2, r2h):
	r = r2h.cmd(r2, 'ic~class 0 some_encrypted_data')
	r = r.strip().split('\n')
	## 4 is a fair number of bad hits in class name.
	return len(r) < 4

def run_tests(o, r2, u, r2h):
	filename = r2h.filename(r2)
	o.binary.hashes(filename, r2h.cmdj(r2, 'itj'))
	o.binary.libraries(r2h.cmdj(r2, 'ilj'))
	if is_decrypted(r2, r2h):
		o.binary.classes(filename, r2h.cmdj(r2, 'icj'))
	else:
		o.logger.warning("The binary is not decrypted. skipping classes list.")

def name_test():
	return "Hashes and binary details"