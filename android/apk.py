from report import *
import glob
import importlib
import os
import r2help
import r2pipe
import shutil
import subprocess
import tempfile
import threading
import utils
import zipfile

def _cleanup(o, e):
	os.remove(o.filename)
	shutil.rmtree(o.apktool)
	shutil.rmtree(o.unzip)
	if e is not None:
		o.logger.error("the analysis has crashed.")
	o.logger.notify("temp files removed, analysis terminated.")

def extract_apk(o):
	o.logger.notify("extracting via apktool.")
	p = subprocess.Popen("apktool d {apk} -f -o {dir}".format(apk=o.filename, dir=o.apktool), stdout=subprocess.PIPE, stderr=None, shell=True)
	p.communicate()
	p.wait()
	o.logger.notify("extracting as zip.")
	with zipfile.ZipFile(o.filename, "r") as zip_ref:
		zip_ref.extractall(o.unzip)

def _apk_analysis(apk):
	try:
		pipes = []
		extract_apk(apk)

		dexes = glob.glob(os.path.join(apk.unzip, "*.dex"))
		for dex in dexes:
			apk.logger.notify("opening {}.".format(os.path.basename(dex)))
			r2 = r2pipe.open(dex)
			if r2 is None:
				apk.logger.error("cannot open file {}.".format(os.path.basename(dex)))
				continue
			r2.filename = dex
			pipes.append(r2)
		if len(pipes) < 1:
			_cleanup(apk, None)
			return

		for file in os.listdir(os.path.join(os.path.dirname(__file__), "tests")):
			if file == "__init__.py" or not file.endswith('.py'):
				continue
			modpath = 'android.tests.' + os.path.splitext(file)[0]
			mod = importlib.import_module(modpath)
			apk.logger.notify(mod.name_test())
			mod.run_tests(apk, pipes, utils, r2help)
		_cleanup(apk, None)
	except Exception as ex:
		raise ex
		_cleanup(apk, ex)
	apk.done.set(True)

class Apk(object):
	"""Apk class for analysis"""
	def __init__(self, temp_filename, done):
		super(Apk, self).__init__()
		self.apktool   = tempfile.mkdtemp()
		self.unzip     = tempfile.mkdtemp()
		self.filename  = temp_filename
		self.logger    = WebLogger()
		self.binary    = BinDetails()
		self.permis    = Permissions()
		self.issues    = Issues()
		self.strings   = Strings()
		self.done      = done
		self.thread    = threading.Thread(target=_apk_analysis, args=(self,))
		self.thread.start()
