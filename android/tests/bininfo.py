SKIP_CLASSES = [
	'Landroid/',
	'Landroidx/',
	'Lcom/facebook/',
	'Lcom/google/android/',
	'Lcom/google/firebase/',
	'Lcom/google/gwt/',
	'Lorg/apache/commons/',
	'Lorg/spongycastle/asn1/',
	'Lorg/spongycastle/jcajce/provider/',
	'Ljavax/',
	'Lkotlin/',
]

def fixname(o, name):
	if o.unzip in name:
		return name[len(o.unzip):]
	return name

def fixlibs(o, libs):
	lnew = []
	for lib in libs:
		lnew.append(fixname(o, lib))
	return lnew

def filter_classes(classes):
	for skip in SKIP_CLASSES:
		classes = list(filter(lambda x: not x['classname'].startswith(skip), classes))
	return classes

def run_tests(o, pipes, u, r2h):
	for r2 in pipes:
		filename = fixname(o, r2h.filename(r2))
		o.binary.hashes(filename, r2h.cmdj(r2, 'itj'))
		o.binary.libraries(fixlibs(o, r2h.cmdj(r2, 'ilj')))
		o.binary.classes(filename, filter_classes(r2h.cmdj(r2, 'icj')))

def name_test():
	return "Hashes and binary details"