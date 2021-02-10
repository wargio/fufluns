/* fufluns - Copyright 2019-2021 - deroad */
/* DEMANGLER */

const JAVA_REGEX = /^L([a-zA-Z\d\/\$_\-]+)(([a-zA-Z\d\.<>\$]+)?(\(\)|\([\[a-zA-Z\d\/\$_\-;]+\))([\[a-zA-Z\d\/\$_\-;]+|[\[ZBSCIJFDV]))?$/;

function java_demangler(array) {
	const JAVA_NATIVE_TYPES = {
		'Z': 'boolean',
		'B': 'byte',
		'S': 'short',
		'C': 'char',
		'I': 'int',
		'J': 'long',
		'F': 'float',
		'D': 'double',
		'V': 'void'
	};

	function demangle_class(x) {
		x = x.replace(/\//g, '.');
		var isArray = x.charAt(0) == '[';
		return x.replace(/^\[?Ljava\.(lang|util)\.|^\[?L|;$/g, '') + (isArray ? '[]' : '');
	}
	var args = [];
	var classname = array[1].replace(/\/|\$/g, '.');
	var method = array[3];
	if (!method) {
		return classname;
	}
	method = method.replace(/\$/g, '.');
	var cargs = array[4];
	var returntype = array[5];
	cargs = cargs.replace(/\(|\)/g, '')
	cargs = cargs.replace(/([ZBSCIJFDV]+)?(\[?L[a-zA-Z\d\/\$_\-]+);/g, '$1;$2;');
	cargs = cargs.replace(/;+/g, ';');
	cargs = cargs.replace(/^;|;$/g, '');
	cargs.split(';').forEach(function(x) {
		if (x.match(/^[\[ZBSCIJFDV]+$/)) {
			var isArray = false;
			x.split('').forEach(function(x) {
				if (returntype.charAt(0) == '[') {
					isArray = true;
					return;
				}
				args.push(JAVA_NATIVE_TYPES[x]) + (isArray ? '[]' : '');
				isArray = false;
			});
		} else {
			args.push(demangle_class(x));
		}
	});
	if (returntype.match(/^[\[ZBSCIJFDV]+$/)) {
		var isArray = returntype.charAt(0) == '[';
		returntype = JAVA_NATIVE_TYPES[isArray ? returntype[1] : returntype] + (isArray ? '[]' : '');
	} else {
		returntype = demangle_class(returntype)
	}
	return returntype + ' ' + classname + method + "(" + args.join(', ') + ')';
}

function demangler(c) {
	try {
		var tmp = c.match(JAVA_REGEX);
		if (tmp) {
			return java_demangler(tmp);
		}
	} catch (e) {
		console.log(e);
	}
	return c;
}

function asAddress(num) {
	num = num.toString(16);
	var max = num.length > 7 ? 16 : 8;
	return '0x' + ('0'.repeat(max - num.length)) + num;
}