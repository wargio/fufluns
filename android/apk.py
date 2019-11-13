from report import *
import importlib
import os
import r2help
import r2pipe
import shutil
import subprocess
import tempfile
import threading
import utils

def _cleanup(o):
	os.remove(o.filename)
	shutil.rmtree(o.directory)
	o.logger.notify("temp files removed, analysis terminated.")

def extract_apk(o):
	p = subprocess.Popen("apktool d {apk} -f -o {dir}".format(apk=o.filename, dir=o.directory), stdout=subprocess.PIPE, stderr=None, shell=True)
	p.communicate()
	p.wait()

def _apk_analysis(apk):
	try:
		apk.logger.notify("extracting apk.")
		extract_apk(apk)

		apk.logger.notify("opening apk.")
		r2 = r2pipe.open("apk://" + apk.filename)
		if r2 is None:
			apk.logger.error("cannot open file.")
			_cleanup(apk)
			return

		for file in os.listdir(os.path.join(os.path.dirname(__file__), "tests")):
			if file == "__init__.py" or not file.endswith('.py'):
				continue
			try:
				modpath = 'android.tests.' + os.path.splitext(file)[0]
				mod = importlib.import_module(modpath)
				apk.logger.notify(mod.name_test())
				mod.run_tests(apk, r2, utils, r2help)
			except Exception as e:
				_cleanup(apk)
				raise e
		_cleanup(apk)
	except Exception as ex:
		raise ex

class Apk(object):
	"""Apk class for analysis"""
	def __init__(self, temp_filename):
		super(Apk, self).__init__()
		self.directory = tempfile.mkdtemp()
		self.filename  = temp_filename
		self.logger    = WebLogger()
		self.binary    = BinDetails()
		self.permis    = Permissions()
		self.issues    = Issues()
		self.thread    = threading.Thread(target=_apk_analysis, args=(self,))
		self.thread.start()
