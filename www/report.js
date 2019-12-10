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


function sort_by_severity(a, b) {
	return b.severity - a.severity;
}

function sort_by_classname(a, b) {
	if (a.name < b.name)
		return -1;
	if (a.name > b.name)
		return 1;
	return 0;
}

function create_markdown_report() {
	if (!window.report) {
		alert('Cannot get report data.');
		return;
	}
	var m = new Markdown(window.report.filename);
	m.addTitle(window.report.plugin + " (" + window.report.filename + ")", Markdown.HEADER_1);
	addMarkdownSection(m, 'addCodeBlock', "Hashes", mapMarkdownBinHashes, window.report.binary.hashes);
	addMarkdownSection(m, 'addCodeBlock', "Libraries", null, window.report.binary.libraries);
	addMarkdownSection(m, 'addList', "Permissions", mapMarkdownPerms, window.report.permissions);
	addMarkdownSection(m, 'addList', "Issues", mapMarkdownIssues, window.report.issues.sort(sort_by_severity));
	addMarkdownSection(m, 'addCodeBlock', "Analysis Logs", mapMarkdownLog, window.report.logs);
	addMarkdownSection(m, 'addList', "Extra (" + Object.keys(window.report.extra).length + ")", mapMarkdownExtra, window.report.extra, true);
	addMarkdownSection(m, 'addCodeBlock', "Source Code (" + window.report.srccode.length + ")", null, window.report.srccode, true);
	addMarkdownSection(m, 'addCodeBlock', "Strings (" + window.report.strings.length + ")", mapMarkdownStrings, window.report.strings, true);
	//addMarkdownSection(m, 'addCodeBlock', "Classes", mapMarkdownBinClasses, window.report.binary.classes.sort(sort_by_classname));
	m.save();
}

function create_textile_report() {
	if (!window.report) {
		alert('Cannot get report data.');
		return;
	}
	var m = new Textile(window.report.filename);
	m.addTitle(window.report.plugin + " (" + window.report.filename + ")", Textile.HEADER_1);
	addTextileSection(m, 'addCodeBlock', "Hashes", mapTextileBinHashes, window.report.binary.hashes);
	addTextileSection(m, 'addCodeBlock', "Libraries", null, window.report.binary.libraries);
	addTextileSection(m, 'addList', "Permissions", mapTextilePerms, window.report.permissions);
	addTextileSection(m, 'addList', "Issues", mapTextileIssues, window.report.issues.sort(sort_by_severity));
	addTextileSection(m, 'addCodeBlock', "Analysis Logs", mapTextileLog, window.report.logs);
	addTextileSection(m, 'addList', "Extra (" + Object.keys(window.report.extra).length + ")", mapTextileExtra, window.report.extra, true);
	addTextileSection(m, 'addCodeBlock', "Source Code (" + window.report.srccode.length + ")", null, window.report.srccode, true);
	addTextileSection(m, 'addCodeBlock', "Strings (" + window.report.strings.length + ")", mapTextileStrings, window.report.strings, true);
	//addTextileSection(m, 'addCodeBlock', "Classes", mapTextileBinClasses, window.report.binary.classes.sort(sort_by_classname));
	m.save();
}

function create_html_report() {
	if (!window.report) {
		alert('Cannot get report data.');
		return;
	}
	var bin = addHtmlSection(window.report.plugin + " (" + window.report.filename + ")");
	addHtmlSubSection(bin, "Hashes", mapHtmlBinHashes, window.report.binary.hashes);
	addHtmlSubSection(bin, "Classes", mapHtmlBinClasses, window.report.binary.classes.sort(sort_by_classname));
	addHtmlSubSection(bin, "Libraries", mapHtmlBinLibs, window.report.binary.libraries);
	addHtmlSection("Permissions", mapHtmlPerms, window.report.permissions);
	addHtmlSection("Issues", mapHtmlIssues, window.report.issues.sort(sort_by_severity));
	addHtmlSection("Strings (" + window.report.strings.length + ")", mapHtmlStrings, window.report.strings, true);
	addHtmlSection("Source Code (" + window.report.srccode.length + ")", mapHtmlSrcCode, window.report.srccode, true);
	addHtmlSection("Extra (" + Object.keys(window.report.extra).length + ")", mapHtmlExtra, window.report.extra, true);
	addHtmlSection("Logs", mapHtmlLog, window.report.logs);
}

function run_app() {
	document.getElementById('id-btn-back').onclick = function() {
		window.location = "/";
	};
	document.getElementById('id-btn-markdown').onclick = create_markdown_report;
	document.getElementById('id-btn-markdown').style.display = 'none';
	document.getElementById('id-btn-textile').onclick = create_textile_report;
	document.getElementById('id-btn-textile').style.display = 'none';
	var session = window.location.hash.substr(1)
	xhr('GET', '/api/report/' + session, function(text) {
		var report = JSON.parse(text);
		if (report.error) {
			alert("Error: " + report.error);
		} else if (report.done) {
			window.report = report
			document.getElementById('id-btn-markdown').style.display = 'block';
			document.getElementById('id-btn-textile').style.display = 'block';
			create_html_report();
		}
	}, function(text) {
		alert("Error:\n" + text);
	});
}