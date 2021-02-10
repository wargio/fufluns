/* fufluns - Copyright 2019-2021 - deroad */
function Markdown(filename) {
	this._data = [];
	this._filename = filename;
	this.addNewLine = function() {
		this._data.push('\n');
	};
	this.addTitle = function(title, heading) {
		if (typeof heading !== "number" || heading < 1) heading = 1;
		else if (heading > 6) heading = 6;
		this._data.push("#".repeat(heading) + " " + title + '\n');
		this.addNewLine();
	};
	this.addBlockquote = function(lines) {
		if (typeof lines === "string") lines = lines.split('\n');
		var self = this;
		lines.forEach(function(line) {
			self._data.push("> " + line + '\n');
		})
		this.addNewLine();
	};
	this.addList = function(list, ordered) {
		if (typeof list === "string") list = list.split('\n');
		var self = this;
		list.forEach(function(elem, idx) {
			var prefix = ordered ? idx.toString() + ". " : "* ";
			self._data.push(prefix + elem + '\n');
		})
		this.addNewLine();
	};
	this.addCodeBlock = function(code) {
		if (Array.isArray(code)) code = code.join('\n');
		this._data.push("```\n" + code.replace(/\n+$/, '') + '\n```');
		this.addNewLine();
	};
	this.addLine = function(line) {
		if (Array.isArray(line)) line = line.join('\n');
		this._data.push(line);
		this.addNewLine();
	};
	this.save = function() {
		var now = (new Date()).getTime();
		var fname = this._filename.replace(/\s/g, '_').replace(/\.[a-zA-Z]+$/, '.' + now + '.md');
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
	Markdown['HEADER_' + i] = i;
}
Markdown.image = function(url, alt) {
	if (!alt) alt = 'placeholder';
	return ['![', alt, '](', url, ')'].join('')
};
Markdown.url = function(url, title) {
	if (!title) title = url;
	return ['[', title, '](', url, ')'].join('')
};
Markdown.italics = function(text) {
	return ['*', text.replace(/([\*_])/g, '\\$1'), '*'].join('')
};
Markdown.bold = function(text) {
	return ['__', text.replace(/([\*_])/g, '\\$1'), '__'].join('')
};
Markdown.code = function(text) {
	if (text.indexOf('`') == 0) text = ' ' + text;
	if (text.indexOf('`') == (text.length - 1)) text += ' ';
	var tick = text.indexOf('`') >= 0 ? '``' : '`';
	return ['`', text, '`'].join('')
};

function addMarkdownSection(m, method, title, newnode, data, collapsed) {
	var size = (data ? ((Array.isArray(data) ? data.length : Object.keys(data).length) || 0) : 0);
	if (size < 1) return;
	m.addTitle(title + ' (' + size.toString() + ') ', Markdown.HEADER_3);
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

function mapMarkdownLog(o) {
	var timestamp = (new Date(o.timestamp * 1000)).toISOString().replace(/\.\d+/g, '');
	var type = o.type.toUpperCase();
	type += " ".repeat(7 - type.length);
	return "[" + timestamp + "] [" + type + "] " + o.log;
}

function mapMarkdownBinHashes(o, num) {
	var t = o.filename + '\n';
	Object.keys(o).sort().forEach(function(k) {
		if (k == 'filename') return;
		t += '    ' + k + ": " + " ".repeat(5 - k.length) + o[k].toUpperCase() + '\n';
	});
	return t.trim();
}

function mapMarkdownBinClasses(o, num) {
	var t = asAddress(o.address) + " " + demangler(o.name) + '\n';
	if (o.methods.length > 0) {
		o.methods.forEach(function(m) {
			t += '    ' + demangler(m) + '\n';
		});
	}
	return t;
}

function mapMarkdownPerms(o) {
	return o.name + "\n\n    " + o.description + "\n";
}

function mapMarkdownIssues(o) {
	var level = "error";
	if (o.severity < 3) level = "info";
	else if (o.severity < 7) level = "warning";
	var t = o.issue + " with CVSS " + o.severity + "\n";
	return t + "    " + o.description;
}

function mapMarkdownStrings(o) {
	var max_filename = 20;
	var max_type = 8;
	var type = o.type.substr(0, max_type);
	var filename = o.filename.substr(0, max_filename);
	var offset = o.offset.toString(16);
	var text = asAddress(offset);
	text += ' | ' + filename + (' '.repeat(max_filename - filename.length));
	text += ' | ' + type + (' '.repeat(max_type - type.length));
	text += ' | ' + o.data.replace(/\n/g, '\\n');
	return text;
}

function mapMarkdownExtra(k, o, num) {
	return (Markdown.code(k) + "\n\n" + (o.length > 0 ? ("```\n" + o + "\n```\n") : "\n"));
}