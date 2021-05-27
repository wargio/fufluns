/* fufluns - Copyright 2019-2021 - deroad */
function Textile(filename) {
	this._data = [];
	this._filename = filename;
	this.addNewLine = function() {
		this._data.push('\n');
	};
	this.addTitle = function(title, heading) {
		if (typeof heading !== "number" || heading < 1) heading = 1;
		else if (heading > 6) heading = 6;
		this._data.push("h" + heading + ". " + title + '\n');
		this.addNewLine();
	};
	this.addBlockquote = function(lines) {
		if (Array.isArray(lines)) lines = lines.join('\n');
		var prefix = lines.indexOf('\n\n') >= 0 ? "bq.. " : "bq. ";
		self._data.push(prefix + lines + '\n');
		this.addNewLine();
	};
	this.addList = function(list, ordered) {
		if (typeof list === "string") list = list.split('\n');
		var self = this;
		list.forEach(function(elem, idx) {
			var prefix = ordered ? "# " : "* ";
			self._data.push(prefix + elem + '\n');
		})
		this.addNewLine();
	};
	this.addCodeBlock = function(code) {
		if (Array.isArray(code)) code = code.join('\n');
		var prefix = code.indexOf('\n\n') >= 0 ? "bc.. " : "bc. ";
		this._data.push(prefix + code.replace(/\n+$/, '') + '\n');
		this.addNewLine();
	};
	this.addLine = function(line) {
		if (Array.isArray(line)) line = line.join('\n');
		this._data.push(line);
		this.addNewLine();
	};
	this.save = function() {
		var now = (new Date()).getTime();
		var fname = this._filename.replace(/\s/g, '_').replace(/\.[a-zA-Z]+$/, '.' + now + '.textile');
		var blob = new Blob(this._data, {
			type: 'text/plain'
		});
		if (window.navigator.msSaveOrOpenBlob) {
			window.navigator.msSaveBlob(blob, fname);
		} else {
			var elem = window.document.createElement('a');
			elem.href = window.URL.createObjectURL(blob);
			elem.download = fname;
			document.body.appendChild(elem);
			elem.click();
			document.body.removeChild(elem);
		}
	};
}
for (var i = 1; i < 7; i++) {
	Textile['HEADER_' + i] = i;
}
Textile.image = function(url, alt) {
	alt = alt ? '(' + alt + ')' : '';
	return ['!', alt, url, '!'].join('')
};
Textile.url = function(url, title) {
	if (!title) title = url;
	return ['"', title, '":', url].join('')
};
Textile.italics = function(text) {
	return ['_', text.replace(/([_])/g, '\\$1'), '_'].join('')
};
Textile.bold = function(text) {
	return ['*', text.replace(/([\*])/g, '\\$1'), '*'].join('')
};
Textile.code = function(text) {
	return ['@', text.replace(/([@])/g, '\\$1'), '@'].join('')
};

function addTextileSection(m, method, title, newnode, data, collapsed) {
	var size = (data ? ((Array.isArray(data) ? data.length : Object.keys(data).length) || 0) : 0);
	if (size < 1) return;
	m.addTitle(title + ' (' + size.toString() + ') ', Textile.HEADER_3);
	if (newnode) {
		if (Array.isArray(data)) {
			data = data.map(newnode)
		} else {
			var tmp = [];
			Object.keys(data).sort().forEach(function(key, i) {
				tmp.push(newnode(key, data[key], i));
			});
			data = tmp;
		}
	}
	m[method ? method : 'addList'](data);
}

function mapTextileLog(o) {
	var timestamp = (new Date(o.timestamp * 1000)).toISOString().replace(/\.\d+/g, '');
	var type = o.type.toUpperCase();
	type += " ".repeat(Math.max(7 - type.length, 0));
	return "[" + timestamp + "] [" + type + "] " + o.log;
}

function mapTextileBinHashes(o, num) {
	var t = o.filename + '\n';
	Object.keys(o).sort().forEach(function(k) {
		if (k == 'filename') return;
		t += '    ' + k + ": " + " ".repeat(Math.max(5 - k.length, 0)) + o[k].toUpperCase() + '\n';
	});
	return t.trim();
}

function mapTextileBinClasses(o, num) {
	var t = asAddress(o.address) + " " + demangler(o.name) + '\n';
	if (o.methods.length > 0) {
		o.methods.forEach(function(m) {
			t += '    ' + demangler(m) + '\n';
		});
	}
	return t;
}

function mapTextilePerms(o) {
	return Textile.code(o.name) + "\n    " + o.description;
}

function mapTextileIssues(o) {
	var level = "error";
	if (o.severity < 3) level = "info";
	else if (o.severity < 7) level = "warning";
	var t = o.issue + " with CVSS " + o.severity + "\n";
	return t + "    " + o.description;
}

function mapTextileStrings(o) {
	var max_filename = 20;
	var max_type = 8;
	var type = o.type.substr(0, max_type);
	var filename = o.filename.substr(0, max_filename);
	var offset = o.offset.toString(16);
	var text = asAddress(offset);
	text += ' | ' + filename + (' '.repeat(Math.max(max_filename - filename.length, 0)));
	text += ' | ' + type + (' '.repeat(Math.max(max_type - type.length, 0)));
	text += ' | ' + o.data.replace(/\n/g, '\\n');
	return text;
}

function mapTextileExtra(k, o, num) {
	return (Textile.code(k) + "\n" + (o.length > 0 ? ("bc.. \n" + o + "\n") : "\n"));
}