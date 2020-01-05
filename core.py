## fufluns - Copyright 2019 - deroad

import ios, android
import tempfile
import shared as sh
import json
import secrets
import time
import threading
import version as fv

def create_temp(data, extension):
	file = tempfile.NamedTemporaryFile(suffix=extension, delete=False)
	fname = file.name
	file.write(data)
	file.close()
	return fname

class NoSession(object):
	def __init__(self, ):
		super(NoSession, self).__init__()
		self._creation    = time.time()

	def valid(self):
		return False
		
class Session(NoSession):
	"""Session status"""
	ANDROID="Android Application"
	IOS="iOS Application"

	def __init__(self, filename, plugin, plugin_name):
		super(Session, self).__init__()
		self._plugin      = plugin
		self._filename    = sh.Shared(filename)
		self._plugin_name = sh.Shared(plugin_name)
		self._error       = sh.Shared(None)

	def valid(self):
		return True

	def report(self):
		if self._plugin.done.get():
			return json.dumps({
				"logs": json.loads(self._plugin.logger.json()),
				"binary": json.loads(self._plugin.binary.json()),
				"permissions": json.loads(self._plugin.permis.json()),
				"issues": json.loads(self._plugin.issues.json()),
				"strings": json.loads(self._plugin.strings.json()),
				"srccode": json.loads(self._plugin.srccode.json()),
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

def zombie_handler(core):
	seconds = 5 * 60
	while True:
		time.sleep(seconds)
		core.clean()

class Core(object):
	"""Core of the application. here we merge all the functionalities."""
	def __init__(self):
		super(Core, self).__init__()
		self._session = sh.SharedMap()
		self.thread   = threading.Thread(target=zombie_handler, args=(self,))
		self.thread.start()

	def clean(self):
		for key in self._session.keys():
			session = self._session.get(key)
			diff = time.time() - session._creation
			if diff > 28800:
				self._session.rem(key)

	def newsession(self):
		identifier = secrets.token_urlsafe(32)
		self._session.set(identifier, NoSession())
		return identifier
	
	def getsession(self, identifier):
		return self._session.get(identifier)

	def analyze(self, identifier, filename, body):
		if not self._session.has(identifier):
			return None
		if filename.endswith(".apk"):
			file = create_temp(body, ".apk")
			self._session.set(identifier, Session(filename, android.Apk(file, sh.Shared(False)), Session.ANDROID))
		elif filename.endswith(".ipa"):
			file = create_temp(body, ".ipa")
			self._session.set(identifier, Session(filename, ios.Ipa(file, sh.Shared(False)), Session.IOS))
		return self._session.get(identifier)

	def version(self):
		return {
			"radare2": fv.radare2(),
			"apkid":   fv.apkid(),
			"apktool": fv.apktool(),
		}
