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
