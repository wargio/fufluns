## fufluns - Copyright 2019-2021 - deroad

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

def run_tests(o, pipes, u, rzh, au):
	for rz in pipes:
		filename = fixname(o, rzh.filename(rz))
		o.binary.hashes(filename, rzh.cmdj(rz, 'itj'))
		o.binary.libraries(fixlibs(o, rzh.cmdj(rz, 'ilj')))
		o.binary.classes(filename, filter_classes(rzh.cmdj(rz, 'icj')))

def name_test():
	return "Hashes and binary details"