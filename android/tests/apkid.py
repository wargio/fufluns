import subprocess
import json

def _apkid(file):
	p = subprocess.Popen("apkid -j {}".format(file), stdout=subprocess.PIPE, stderr=None, shell=True)
	(stdout, junk) = p.communicate()
	p.wait()
	try:
		return json.loads(stdout)
	except Exception as e:
		print(e)
		return None

def run_tests(apk, pipes, u, r2h, au):
	result = _apkid(apk.filename)
	if result is None:
		apk.logger.error("APKiD error: Check tool logs for more infos.")
		return

	if "files" not in result:
		apk.logger.error("APKiD error: Cannot find 'files' key in the data.")
		return

	pad_key = (" " * 4) + "* "
	pad_val = (" " * 8) + "- "

	text = ""
	for file in result['files']:
		text += file['filename'].split('!')[1] + "\n"
		matches = sorted(file['matches'].keys())
		for key in matches:
			text += pad_key + key + "\n"
			text += pad_val + ("\n" + pad_val).join(file['matches'][key]) + "\n"
	apk.extra.add("APKiD", text.strip())




def name_test():
	return "APKiD."