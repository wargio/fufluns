function run_app() {

	['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
		document.getElementById('id-drop-area').addEventListener(eventName, preventDefaults, false);
	});

	['dragenter', 'dragover'].forEach(eventName => {
		document.getElementById('id-drop-area').addEventListener(eventName, highlight, false);
	});

	['dragleave', 'drop'].forEach(eventName => {
		document.getElementById('id-drop-area').addEventListener(eventName, unhighlight, false);
	});

	document.getElementById('id-drop-area').addEventListener('drop', handleDrop, false);
}

function handleDrop(e) {
	var dt = e.dataTransfer
	var files = dt.files

	handleFiles(files);
}

function preventDefaults(e) {
	e.preventDefault();
	e.stopPropagation();
}

function highlight(e) {
	document.getElementById('id-drop-area').classList.add('highlight');
}

function unhighlight(e) {
	document.getElementById('id-drop-area').classList.remove('highlight');
}

function handleFile(files) {
	Array.from(files).forEach(uploadFile);
}

function uploadFile(file) {
	var url = '/api/analyze';
	var xhr = new XMLHttpRequest();
	var formData = new FormData();
	xhr.open('POST', url, true);

	xhr.addEventListener('readystatechange', function(e) {
		if (xhr.readyState == 4 && xhr.status == 200) {
			try {
				var resp = JSON.parse(xhr.responseText);
				if (resp.error) {
					alert("Error: " + resp.error);
				} else {
					alert("File uploaded.");
					window.location.href = "/ui/analysis.html";
				}
			} catch(ee) {
				alert("Exception.\n" + ee);
			}
		} else if (xhr.readyState == 4 && xhr.status != 200) {
			alert("Upload failed.\n" + e.responseText);
		}
	});

	formData.append('file', file);
	xhr.send(formData);
}