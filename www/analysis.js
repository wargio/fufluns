var LOGS_TIMEOUT = 1000

function run_app() {
	setTimeout(updateLogs, 250);
}

function mapLogs(o) {
	return "<span class=\"log-" + o.type + "\">[" + o.type.toUpperCase() + "] " + o.log + "</span>";
}

function getLogs(elem) {
	var xhr = new XMLHttpRequest();
	xhr.open('GET', '/api/logs', true);
	xhr.addEventListener('readystatechange', function(e) {
		if (xhr.readyState == 4 && xhr.status == 200) {
			var logs = JSON.parse(xhr.responseText);
			if (logs.error) {
				alert("Error: " + resp.error);
			} else {
				elem.innerHTML = logs.map(mapLogs).join("\n");
				setTimeout(updateLogs, LOGS_TIMEOUT);
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