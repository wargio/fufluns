/* async XMLHttpRequest */
function xhr(method, path, onsuccess, onfail) {
	var o = new XMLHttpRequest();
	o.open(method, path, true);
	o.addEventListener('readystatechange', function(e) {
		if (o.readyState == 4 && o.status == 200) {
			if (onsuccess) onsuccess(o.responseText);
		} else if (o.readyState == 4 && o.status != 200) {
			if (onfail) onfail(o.responseText);
		}
	});
	o.send();
}

/* create element */
function ce(type, classname, extra) {
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

function collapsable(parent, unique, classname, show) {
	unique = unique.replace(/\s+/g, '-');
	var container = document.createElement('div');
	var button = ce('a', "not-link", show ? '[hide]' : '[show]');
	button.id = "id-button-" + unique;
	button.href = "#";
	container.id = "id-container-" + unique;
	container.style.display = show ? 'block' : 'none';
	container.className = classname || '';
	button.onclick = new Function(
		"var c = document.getElementById('" + container.id + "');" +
		"c.style.display = (c.style.display == 'block' ? 'none' : 'block');" +
		"var b = document.getElementById('" + button.id + "');" +
		"b.textContent = (c.style.display == 'block' ? '[show]' : '[hide]');"
	);
	parent.appendChild(button);
	parent.appendChild(container);
	return container;
}

function addSubSection(tparent, title, newnode, data, collapsed) {
	var size = (data ? (data.length || 0) : 0);
	tparent.appendChild(ce('span', "report-title report-section", title + ' (' + size.toString() + ') '));
	var parent = collapsable(tparent, 'section-' + title.toLowerCase(), 'block-collapse', size < 30);
	if (newnode) {
		data.forEach(function(o, i) {
			newnode(o, parent, i);
		});
	}
	tparent.appendChild(document.createElement('br'));
}

function addSection(title, newnode, data, collapsed) {
	var pre = ce("pre", "logs-code");
	if (newnode) {
		document.body.appendChild(document.createElement('br'));
	}
	document.body.appendChild(ce("div", "logs-code logs-btn-container", [ce('span', "report-title", title)]));
	document.body.appendChild(pre);
	if (collapsed && newnode) {
		var c = collapsable(pre, 'main-section-' + title.toLowerCase(), 'block-collapse', false);
		data.forEach(function(o) {
			newnode(o, c);
		});
	} else if (newnode) {
		data.forEach(function(o) {
			newnode(o, pre);
		});
	}
	return pre;
}

function mapLog(o, parent) {
	var timestamp = (new Date(o.timestamp * 1000)).toISOString().replace(/\.\d+/g, '');
	var type = o.type.toUpperCase();
	type += " ".repeat(7 - type.length);
	var text = "[" + timestamp + "] [" + type + "] " + o.log + "\n";
	parent.appendChild(ce("span", "log-" + o.type, text));
}

function mapBinHashes(o, parent, num) {
	if (num > 0) parent.appendChild(document.createElement('br'));
	parent.appendChild(ce("span", "log-notify", '- ' + o.filename + ' \n'));
	Object.keys(o).sort().forEach(function(k) {
		if (k == 'filename') return;
		parent.appendChild(ce("span", "log-notify", '  + ' + k + ": " + " ".repeat(5 - k.length) + o[k].toUpperCase() + '\n'));
	});
}

function mapBinClasses(o, parent, num) {
	if (num > 0) parent.appendChild(document.createElement('br'));
	parent.appendChild(ce("span", "log-notify", '- ' + o.name + ' '));
	var p = collapsable(parent, 'class-' + num.toString(), 'block-collapse');
	o.methods.forEach(function(m) {
		p.appendChild(ce("span", "log-notify", '  + ' + m + '\n'));
	});
}

function mapBinLibs(o, parent, num) {
	parent.appendChild(ce("span", "log-notify", '- ' + o + ' \n'));
}

function mapPerms(o, parent) {
	parent.appendChild(ce("span", "log-info", '- ' + o.name + "\n"));
	parent.appendChild(ce("span", "log-notify", "    " + o.description + "\n"));
}

function mapIssues(o, parent) {
	var level = "error";
	if (o.severity < 3) level = "info";
	else if (o.severity < 7) level = "warning";
	parent.appendChild(ce("span", "log-" + level, '- ' + o.issue + " with CVSS " + o.severity + "\n"));
	parent.appendChild(ce("span", "log-notify", "    " + o.description + "\n"));
}

function mapStrings(o, parent) {
	var max_filename = 20;
	var max_type = 8;
	var type = o.type.substr(0, max_type);
	var filename = o.filename.substr(0, max_filename);
	var offset = o.offset.toString(16);
	var text = '0x';
	text += ('0'.repeat(8 - offset.length)) + offset;
	text += ' | ' + filename + (' '.repeat(max_filename - filename.length));
	text += ' | ' + type + (' '.repeat(max_type - type.length));
	text += ' | ' + o.data.replace(/\n/g, '\\n');
	parent.appendChild(ce("span", "log-notify", text + "\n"));
}

function sort_by_severity(a, b) {
	return b.severity - a.severity;
}

function run_app() {
	document.getElementById('id-btn-back').onclick = function() {
		window.location = "/";
	};
	xhr('GET', '/api/report', function(text) {
		var report = JSON.parse(text);
		console.log(report);
		if (report.done) {
			var bin = addSection(report.plugin + " (" + report.filename + ")");
			addSubSection(bin, "Hashes", mapBinHashes, report.binary.hashes);
			addSubSection(bin, "Classes", mapBinClasses, report.binary.classes);
			addSubSection(bin, "Libraries", mapBinLibs, report.binary.libraries);
			addSection("Permissions", mapPerms, report.permissions);
			addSection("Issues", mapIssues, report.issues.sort(sort_by_severity));
			addSection("Strings (" + report.strings.length + ")", mapStrings, report.strings, report.strings.length > 100);
			addSection("Logs", mapLog, report.logs);
		}
	});
}