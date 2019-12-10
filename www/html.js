/* create element */
function _ce(type, classname, extra) {
	var e = document.createElement(type);
	if (classname)
		e.className = classname;
	if (typeof extra === "string") {
		e.textContent = extra
	} else if (Array.isArray(extra)) {
		extra.forEach(function(x) {
			e.appendChild(x);
		});
	}
	return e;
}

function _collapsable(parent, unique, classname, show) {
	unique = unique.replace(/\s+/g, '-');
	var container = document.createElement('div');
	var button = _ce('a', "not-link", show ? '[hide]' : '[show]');
	button.id = "id-button-" + unique;
	button.href = "#";
	container.id = "id-container-" + unique;
	container.style.display = show ? 'block' : 'none';
	container.className = classname || '';
	button.onclick = new Function(
		"var c = document.getElementById('" + container.id + "');" +
		"var b = document.getElementById('" + button.id + "');" +
		"b.textContent = (c.style.display == 'block' ? '[show]' : '[hide]');" +
		"c.style.display = (c.style.display == 'block' ? 'none' : 'block');" +
		"arguments[0].preventDefault();"
	);
	parent.appendChild(button);
	parent.appendChild(container);
	return container;
}

function addHtmlSubSection(tparent, title, newnode, data, collapsed) {
	var size = (data ? (data.length || 0) : 0);
	if (size < 1) return;
	tparent.appendChild(_ce('span', "report-title report-section", title + ' (' + size.toString() + ') '));
	var parent = _collapsable(tparent, 'section-' + title.toLowerCase(), 'block-collapse', size < 30);
	if (newnode) {
		data.forEach(function(o, i) {
			newnode(o, parent, i);
		});
	}
	tparent.appendChild(document.createElement('br'));
}

function addHtmlSection(title, newnode, data, collapsed) {
	var size = (data ? ((Array.isArray(data) ? data.length : Object.keys(data).length) || 0) : -1);
	if (size == 0) return;
	var pre = _ce("pre", "logs-code");
	if (newnode) {
		document.body.appendChild(document.createElement('br'));
	}
	document.body.appendChild(_ce("div", "logs-code logs-btn-container", [_ce('span', "report-title", title)]));
	document.body.appendChild(pre);
	if (collapsed && newnode) {
		var c = _collapsable(pre, 'main-section-' + title.toLowerCase(), 'block-collapse', false);
		if (Array.isArray(data)) {
			data.forEach(function(o, i) {
				newnode(o, c, i);
			});
		} else {
			Object.keys(data).sort().forEach(function(key, i) {
				newnode(key, data[key], c, i);
			});
		}
	} else if (newnode) {
		if (Array.isArray(data)) {
			data.forEach(function(o, i) {
				newnode(o, pre, i);
			});
		} else {
			Object.keys(data).sort().forEach(function(key, i) {
				newnode(key, data[key], pre, i);
			});
		}
	}
	return pre;
}

function mapHtmlLog(o, parent) {
	var timestamp = (new Date(o.timestamp * 1000)).toISOString().replace(/\.\d+/g, '');
	var type = o.type.toUpperCase();
	type += " ".repeat(7 - type.length);
	var text = "[" + timestamp + "] [" + type + "] " + o.log + "\n";
	parent.appendChild(_ce("span", "log-" + o.type, text));
}

function mapHtmlBinHashes(o, parent, num) {
	if (num > 0) parent.appendChild(document.createElement('br'));
	parent.appendChild(_ce("span", "log-notify", '- ' + o.filename + ' \n'));
	Object.keys(o).sort().forEach(function(k) {
		if (k == 'filename') return;
		parent.appendChild(_ce("span", "log-notify", '  + ' + k + ": " + " ".repeat(5 - k.length) + o[k].toUpperCase() + '\n'));
	});
}

function mapHtmlBinClasses(o, parent, num) {
	if (num > 0) parent.appendChild(document.createElement('br'));
	parent.appendChild(_ce("span", "log-notify", '- ' + asAddress(o.address) + " " + demangler(o.name) + ' '));
	if (o.methods.length > 0) {
		var p = _collapsable(parent, 'class-' + num.toString(), 'block-collapse');
		o.methods.forEach(function(m) {
			p.appendChild(_ce("span", "log-notify", '  + ' + demangler(m) + '\n'));
		});
	}
}

function mapHtmlBinLibs(o, parent, num) {
	parent.appendChild(_ce("span", "log-notify", o + ' \n'));
}

function mapHtmlPerms(o, parent) {
	parent.appendChild(_ce("span", "log-info", '- ' + o.name + "\n"));
	parent.appendChild(_ce("span", "log-notify", "    " + o.description + "\n"));
}

function mapHtmlIssues(o, parent) {
	var level = "error";
	if (o.severity < 3) level = "info";
	else if (o.severity < 7) level = "warning";
	parent.appendChild(_ce("span", "log-" + level, '- ' + o.issue + " with CVSS " + o.severity + "\n"));
	parent.appendChild(_ce("span", "log-notify", "    " + o.description + "\n"));
}

function mapHtmlStrings(o, parent) {
	var max_filename = 20;
	var max_type = 8;
	var type = o.type.substr(0, max_type);
	var filename = o.filename.substr(0, max_filename);
	var offset = o.offset.toString(16);
	var text = asAddress(offset);
	text += ' | ' + filename + (' '.repeat(max_filename - filename.length));
	text += ' | ' + type + (' '.repeat(max_type - type.length));
	text += ' | ' + o.data.replace(/\n/g, '\\n');
	parent.appendChild(_ce("span", "log-notify", text + "\n"));
}

function mapHtmlSrcCode(o, parent, num) {
	parent.appendChild(_ce("span", "log-notify", o + "\n"));
}

function mapHtmlExtra(k, o, parent, num) {
	if (num > 0) parent.appendChild(document.createElement('br'));
	parent.appendChild(_ce("span", "log-notify", '- ' + k + " "));
	if (o.length > 0) {
		var p = _collapsable(parent, 'extra-' + num.toString(), 'block-collapse');
		p.appendChild(_ce("span", "log-notify", o));
	}
}