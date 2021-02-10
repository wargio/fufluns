## fufluns - Copyright 2019-2021 - deroad

def is_decrypted(rz, rzh):
	r = rzh.cmd(rz, 'ic~class 0 some_encrypted_data')
	r = r.strip().split('\n')
	## 4 is a fair number of bad hits in class name.
	return len(r) < 4

def run_tests(o, rz, u, rzh):
	filename = rzh.filename(rz)
	o.binary.hashes(filename, rzh.cmdj(rz, 'itj'))
	o.binary.libraries(rzh.cmdj(rz, 'ilj'))
	if is_decrypted(rz, rzh):
		o.binary.classes(filename, rzh.cmdj(rz, 'icj'))
	else:
		o.logger.warning("The binary is not decrypted. skipping classes list.")

def name_test():
	return "Hashes and binary details"