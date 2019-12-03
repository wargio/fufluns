
def run_tests(o, pipes, u, r2h):
	for r2 in pipes:
		filename = r2h.filename(r2)
		o.binary.hashes(filename, r2h.cmdj(r2, 'itj'))
		o.binary.libraries(r2h.cmdj(r2, 'ilj'))
		o.binary.classes(filename, r2h.cmdj(r2, 'icj'))

def name_test():
	return "Hashes and binary details"