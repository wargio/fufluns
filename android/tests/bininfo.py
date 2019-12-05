
def fixname(o, name):
	if o.unzip in name:
		return name[len(o.unzip):]
	return name

def fixlibs(o, libs):
	lnew = []
	for lib in libs:
		lnew.append(fixname(o, lib))
	return lnew


def run_tests(o, pipes, u, r2h):
	for r2 in pipes:
		filename = fixname(o, r2h.filename(r2))
		o.binary.hashes(filename, r2h.cmdj(r2, 'itj'))
		o.binary.libraries(fixlibs(o, r2h.cmdj(r2, 'ilj')))
		o.binary.classes(filename, r2h.cmdj(r2, 'icj'))

def name_test():
	return "Hashes and binary details"