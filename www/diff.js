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

Array.prototype.toObject = function() {
	var o = {};
	this.forEach(function(x) {
		o[x] = true;
	});
	return o;
}

function map_name(x) {
	return x.name;
}

function map_issue(x) {
	return x.issue;
	var p = x.issue.indexOf("(");
	return p > 0 ? x.issue.substr(0, p).trim() : x.issue;
}

function diff_maps(a, b) {
	var d = {
		removed: [],
		added: [],
		common: []
	};
	for (var k1 in a) {
		if (!b[k1]) {
			d.removed.push(k1);
		} else {
			d.common.push(k1);
		}
	}
	for (var k2 in b) {
		if (!a[k2]) {
			d.added.push(k2);
		}
	}
	return d;
}

function _title(x) {
	return x[0].toUpperCase() + x.substr(1);
}

function print_diff(name, method, parent, data1, data2) {
	data1 = method ? method(data1) : data1.toObject();
	data2 = method ? method(data2) : data2.toObject();
	var missing = diff_maps(data1, data2);
	if (missing.removed.length < 1 && missing.added.length < 1) return;
	parent.appendChild(_ce("span", "log-notify", _title(name) + " missing values:"));
	parent.appendChild(_ce("br"));
	if (missing.removed.length > 0) {
		parent.appendChild(_ce("span", "log-error", "- Removed:\n"));
		missing.removed.forEach(function(x) {
			parent.appendChild(_ce("span", "log-error", "  + " + JSON.stringify(x) + "\n"));
		});
	}
	if (missing.added.length > 0) {
		parent.appendChild(_ce("span", "log-info", "- Added:\n"));
		missing.added.forEach(function(x) {
			parent.appendChild(_ce("span", "log-info", "  + " + JSON.stringify(x) + "\n"));
		});
	}
	if (missing.common.length > 0) {
		parent.appendChild(_ce("span", "log-debug", "- Common:\n"));
		missing.common.forEach(function(x) {
			parent.appendChild(_ce("span", "log-debug", "  + " + JSON.stringify(x) + "\n"));
		});
	}
}

var prepare = {
	"permissions": function(data) {
		return data.map(map_name).toObject();
	},
	"issues": function(data) {
		return data.map(map_issue).toObject();
	},
	"extra": function(data) {
		return Object.keys(data).toObject();
	},
}

function diff(parent, obj1, obj2) {
	parent.innerHTML = '';
	var objkeys = Object.keys(obj1);
	for (var i = 0; i < objkeys.length; i++) {
		print_diff(objkeys[i], prepare[objkeys[i]], parent, obj1[objkeys[i]], obj2[objkeys[i]]);
	}
	console.log("done.");
}

function run_app() {
	document.getElementById('id-btn-back').onclick = function() {
		window.location = "/";
	};
	document.getElementById('id-btn-diff').onclick = function() {
		var result = document.getElementById('id-result');
		var text1 = document.getElementById('id-text-1').value;
		var text2 = document.getElementById('id-text-2').value;
		if (text1.length < 1) {
			alert('File 1 is empty');
			return;
		} else if (text2.length < 1) {
			alert('File 2 is empty');
			return;
		}
		try {
			text1 = JSON.parse(text1);
			text2 = JSON.parse(text2);
			diff(result, text1, text2);
		} catch (e) {
			console.log(e);
			alert(e);
		}
	};
}