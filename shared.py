import threading

class Shared(object):
	"""Shared object"""
	def __init__(self, data):
		super(Shared, self).__init__()
		self.lock = threading.Lock()
		self.data  = data

	def get(self):
		self.lock.acquire()
		data = self.data
		self.lock.release()
		return data

	def set(self, data):
		self.lock.acquire()
		self.data = data
		self.lock.release()

class SharedMap(object):
	"""SharedMap object"""
	def __init__(self, data={}):
		super(SharedMap, self).__init__()
		self.lock = threading.Lock()
		self.data = data

	def keys(self):
		self.lock.acquire()
		ret = list(self.data.keys())
		self.lock.release()
		return ret

	def has(self, key):
		self.lock.acquire()
		ret = key in self.data
		self.lock.release()
		return ret

	def get(self, key):
		self.lock.acquire()
		data = None
		if key in self.data:
			data = self.data[key]
		self.lock.release()
		return data

	def set(self, key, data):
		self.lock.acquire()
		self.data[key] = data
		self.lock.release()

	def rem(self, key):
		self.lock.acquire()
		try:
			del self.data[key]
		except KeyError:
			pass
		self.lock.release()

