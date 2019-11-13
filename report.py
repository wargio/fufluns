import threading
import shared as sh
import json

PERMISSION_NAME='Name'
PERMISSION_DESC='Description'

ISSUE_TBL_NAME='Issue'
ISSUE_TBL_DESC='Description'
ISSUE_TBL_SEVR='Severity'

class BinDetails(object):
	"""Contains the details of the binary, like hashes, etc.."""
	def __init__(self):
		super(BinDetails, self).__init__()
		self._details = sh.Shared(None)
		self._hashes = sh.Shared(None)

	def detail(self, data):
		self._details.set(data)

	def hashes(self, data):
		self._hashes.set(data)

	def json(self):
		self.lock.acquire()
		ret = json.dumps({
			"details": self._details.get(),
			"hashes": self._hashes.get()
		})
		self.lock.release()
		return ret

class Permissions(object):
	"""Class used to list all the permissions requested by the mobile application"""
	def __init__(self):
		super(Permissions, self).__init__()
		self.perms = []
		self.lock  = threading.Lock()

	def add(self, name, description):
		self.lock.acquire()
		self.perms.append({
			PERMISSION_NAME: name,
			PERMISSION_DESC: description
		})
		self.lock.release()

	def json(self):
		self.lock.acquire()
		ret = json.dumps(self.perms)
		self.lock.release()
		return ret

class Issues(object):
	"""Issues linked to the binary"""

	def __init__(self):
		super(Issues, self).__init__()
		self.issues = []
		self.lock  = threading.Lock()

	def add(self, detail, description, severity):
		self.lock.acquire()
		self.issues.append({
			ISSUE_TBL_NAME: detail,
			ISSUE_TBL_DESC: description,
			ISSUE_TBL_SEVR: severity,
		})
		self.lock.release()

	def json(self):
		self.lock.acquire()
		ret = json.dumps(self.issues)
		self.lock.release()
		return ret

class WebLogger(object):
	"""Class used to creat loggin features via web interface."""
	def __init__(self):
		super(WebLogger, self).__init__()
		self.logs = []
		self.lock  = threading.Lock()

	def error(self, message):
		self.lock.acquire()
		self.logs.append({"type": "error", "log": message})
		self.lock.release()

	def warning(self, message):
		self.lock.acquire()
		self.logs.append({"type": "warning", "log": message})
		self.lock.release()

	def info(self, message):
		self.lock.acquire()
		self.logs.append({"type": "info", "log": message})
		self.lock.release()

	def json(self):
		self.lock.acquire()
		ret = json.dumps(self.logs)
		self.lock.release()
		return ret