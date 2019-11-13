var LOGS_TIMEOUT = 1000

function run_app() {
	setTimeout(updateLogs, 250);
}


function mapLogs(o) {
	var timestamp = (new Date(o.timestamp * 1000)).toISOString().replace(/\.\d+/g, '');
	var type = o.type.toUpperCase();
	type += " ".repeat(7 - type.length)
	return "<span class=\"log-" + o.type + "\">[" + timestamp + "] [" + type + "] " + o.log + "</span>";
}

function getLogs(elem) {
	var xhr = new XMLHttpRequest();
	xhr.open('GET', '/api/logs', true);
	xhr.addEventListener('readystatechange', function(e) {
		if (xhr.readyState == 4 && xhr.status == 200) {
			var logs = JSON.parse(xhr.responseText);
			if (logs.error) {
				alert("Error: " + logs.error);
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