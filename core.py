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
	ANDROID="Android"
	IOS="IOS"

	def __init__(self, filename, plugin, plugin_name):
		super(Session, self).__init__()
		self._plugin      = plugin
		self._filename    = sh.Shared(filename)
		self._plugin_name = sh.Shared(plugin_name)
		self._error       = sh.Shared(None)

	def logs(self):
		return self._plugin.logger.json()

	def plugin(self):
		return json.dumps({
			"plugin": self._plugin_name.get(),
			"filename": self._filename.get()
		})

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
			self._session.set(Session(filename, android.Apk(file), Session.ANDROID))
		elif filename.endswith(".ipa"):
			file = create_temp(body, ".ipa")
			self._session.set(Session(filename, ios.Ipa(file), Session.IOS))
		return self._session.get()