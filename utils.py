## fufluns - Copyright 2019,2020 - deroad

def permission(o, name, description):
	o.permis.add(name, description)

def test(o, b, detail, description, severity):
	if b:
		o.logger.info("[OK] {}".format(detail))
	else:
		o.logger.warning("[XX] {}".format(detail))
		o.issues.add(detail, description, severity)

def dk(o, keys, default=None):
	keys = keys.split('.')
	if o is not None:
		for k in keys:
			if k not in o:
				o = None
				break
			o = o[k]
	if o is not None:
		return o
	return default

def not_serializable(o):
	return '<not serializable: {}>'.format(type(o).__qualname__)