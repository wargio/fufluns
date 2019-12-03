import threading
import json
import time
from utils import dk

PERMISSION_NAME='name'
PERMISSION_DESC='description'

ISSUE_TBL_NAME='issue'
ISSUE_TBL_DESC='description'
ISSUE_TBL_SEVR='severity'

STRINGS_TBL_OFFSET='offset'
STRINGS_TBL_DATA  ='data'
STRINGS_TBL_TYPE  ='type'
STRINGS_TBL_FILE  ='filename'

BINDETAILS_DETAILS_LIBRARIES='libraries'
BINDETAILS_DETAILS_CLASSES='classes'
BINDETAILS_DETAILS_HASHES='hashes'

def bin_methods(c):
	return [dk(x, 'name', '(null)') for x in dk(c, 'methods', [])]

class BinDetails(object):
	"""Contains the details of the binary, like hashes, etc.."""
	def __init__(self):
		super(BinDetails, self).__init__()
		self._details = {
			BINDETAILS_DETAILS_LIBRARIES: [],
			BINDETAILS_DETAILS_CLASSES: [],
			BINDETAILS_DETAILS_HASHES: []
		}
		self.lock  = threading.Lock()

	def libraries(self, data):
		self.lock.acquire()
		self._details[BINDETAILS_DETAILS_LIBRARIES].extend(data)
		self.lock.release()

	def classes(self, filename, data):
		self.lock.acquire()
		dc = []
		for c in data:
			dc.append({
				'filename': filename,
				'name': dk(c, 'classname', "(null)"),
				'super': dk(c, 'super'),
				'address': dk(c, 'addr', 0),
				'methods': bin_methods(c),
			})
		self._details[BINDETAILS_DETAILS_CLASSES].extend(dc)
		self.lock.release()

	def hashes(self, filename, data):
		data['filename'] = filename
		self.lock.acquire()
		self._details[BINDETAILS_DETAILS_HASHES].append(data)
		self.lock.release()

	def json(self):
		self.lock.acquire()
		ret = json.dumps(self._details)
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

class Strings(object):
	"""Strings linked to the binary"""

	def __init__(self):
		super(Strings, self).__init__()
		self.strings = []
		self.lock  = threading.Lock()

	def add(self, filename, stype, offset, string):
		self.lock.acquire()
		self.strings.append({
			STRINGS_TBL_DATA:   string,
			STRINGS_TBL_FILE:   filename,
			STRINGS_TBL_TYPE:   stype,
			STRINGS_TBL_OFFSET: offset,
		})
		self.lock.release()

	def json(self):
		self.lock.acquire()
		ret = json.dumps(self.strings)
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
		self.logs.append({"timestamp": time.time(), "log": message, "type": "error"})
		self.lock.release()

	def warning(self, message):
		self.lock.acquire()
		self.logs.append({"timestamp": time.time(), "log": message, "type": "warning"})
		self.lock.release()

	def notify(self, message):
		self.lock.acquire()
		self.logs.append({"timestamp": time.time(), "log": message, "type": "notify"})
		self.lock.release()

	def info(self, message):
		self.lock.acquire()
		self.logs.append({"timestamp": time.time(), "log": message, "type": "info"})
		self.lock.release()

	def json(self):
		self.lock.acquire()
		ret = json.dumps(self.logs)
		self.lock.release()
		return ret