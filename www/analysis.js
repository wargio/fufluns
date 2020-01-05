/* fufluns - Copyright 2019 - deroad */
var LOGS_TIMEOUT = 1000

function run_app() {
	window.updateId = setTimeout(updateLogs, 250);
	document.getElementById('id-btn-polling').onclick = function() {
		var x = document.getElementById('id-btn-polling');
		if (!x.value.toLowerCase().indexOf('stop')) {
			x.value = 'Start Polling';
			x.className = x.className.replace(/red/, 'green')
			clearTimeout(window.updateId);
			window.updateId = null;
		} else {
			x.value = 'Stop Polling';
			x.className = x.className.replace(/green/, 'red')
			window.updateId = setTimeout(updateLogs, LOGS_TIMEOUT);
		}
	};
	document.getElementById('id-btn-back').onclick = function() {
		window.location = "/";
	};
}


function mapLogs(o) {
	var timestamp = (new Date(o.timestamp * 1000)).toISOString().replace(/\.\d+/g, '');
	var type = o.type.toUpperCase();
	type += " ".repeat(7 - type.length)
	return "<span class=\"log-" + o.type + "\">[" + timestamp + "] [" + type + "] " + o.log + "</span>";
}

function getLogs(elem) {
	var session = window.location.hash.substr(1)
	var xhr = new XMLHttpRequest();
	xhr.open('GET', '/api/report/' + session, true);
	xhr.addEventListener('readystatechange', function(e) {
		if (xhr.readyState == 4 && xhr.status == 200) {
			var report = JSON.parse(xhr.responseText);
			if (report.error) {
				alert("Error: " + report.error);
			} else if (report.done) {
				window.location = "/ui/report.html" + window.location.hash;
			} else {
				elem.innerHTML = report.logs.map(mapLogs).join("\n");
				window.updateId = setTimeout(updateLogs, LOGS_TIMEOUT);
			}
		} else if (xhr.readyState == 4 && xhr.status != 200) {
			elem.textContent = e.responseText;
		}
	});
	xhr.send();
}

function updateLogs(argument) {
	getLogs(document.getElementById('id-logs'));
};