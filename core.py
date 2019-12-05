import ios, android
import tempfile
import shared as sh
import json

def create_temp(data, extension):
	file = tempfile.NamedTemporaryFile(suffix=extension, delete=False)
	fname = file.name
	file.write(data)
	file.close()
	return fname

class Session(object):
	"""Session status"""
	ANDROID="Android Application"
	IOS="iOS Application"

	def __init__(self, filename, plugin, plugin_name):
		super(Session, self).__init__()
		self._plugin      = plugin
		self._filename    = sh.Shared(filename)
		self._plugin_name = sh.Shared(plugin_name)
		self._error       = sh.Shared(None)

	def report(self):
		if self._plugin.done.get():
			return json.dumps({
				"logs": json.loads(self._plugin.logger.json()),
				"binary": json.loads(self._plugin.binary.json()),
				"permissions": json.loads(self._plugin.permis.json()),
				"issues": json.loads(self._plugin.issues.json()),
				"strings": json.loads(self._plugin.strings.json()),
				"extra": json.loads(self._plugin.extra.json()),
				"plugin": self._plugin_name.get(),
				"filename": self._filename.get(),
				"done": True
			})
		else:
			return json.dumps({
				"logs": json.loads(self._plugin.logger.json()),
				"plugin": self._plugin_name.get(),
				"filename": self._filename.get(),
				"done": False
			});

	def error(self):
		return self._error.get()
		

class Core(object):
	"""Core of the application. here we merge all the functionalities."""
	def __init__(self):
		super(Core, self).__init__()
		self._session = sh.Shared(None)
	
	def session(self):
		return self._session.get()

	def new(self, filename, body):
		if filename.endswith(".apk"):
			file = create_temp(body, ".apk")
			self._session.set(Session(filename, android.Apk(file, sh.Shared(False)), Session.ANDROID))
		elif filename.endswith(".ipa"):
			file = create_temp(body, ".ipa")
			self._session.set(Session(filename, ios.Ipa(file, sh.Shared(False)), Session.IOS))
		return self._session.get()