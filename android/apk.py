## fufluns - Copyright 2019-2021 - deroad

from report import BinDetails
from report import Permissions
from report import Issues
from report import SourceCode
from report import Strings
from report import Extra
from report import WebLogger
import glob
import importlib
import os
import rzhelp
import rzpipe
import shutil
import subprocess
import tempfile
import threading
import utils
import zipfile
import android.utils as au

def _cleanup(o, pipes, crashed):
	os.remove(o.filename)
	shutil.rmtree(o.apktool)
	shutil.rmtree(o.unzip)
	for rz in pipes:
		rz.quit()
	if crashed:
		o.logger.error(">> THE TOOL HAS CRASHED. CHECK THE LOGS <<")
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
	pipes = []
	try:
		extract_apk(apk)

		dexes = glob.glob(os.path.join(apk.unzip, "*.dex"))
		for dex in dexes:
			apk.logger.notify("opening {}.".format(os.path.basename(dex)))
			rz = rzpipe.open(dex)
			if rz is None:
				apk.logger.error("cannot open file {}.".format(os.path.basename(dex)))
				continue
			rz.filename = dex
			pipes.append(rz)
		if len(pipes) < 1:
			_cleanup(apk, pipes, False)
			return

		for file in os.listdir(os.path.join(os.path.dirname(__file__), "tests")):
			if file == "__init__.py" or not file.endswith('.py'):
				continue
			modpath = 'android.tests.' + os.path.splitext(file)[0]
			mod = importlib.import_module(modpath)
			apk.logger.notify(mod.name_test())
			mod.run_tests(apk, pipes, utils, rzhelp, au)
	except Exception as ex:
		_cleanup(apk, pipes, True)
		raise ex
	_cleanup(apk, pipes, False)
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
		self.extra     = Extra()
		self.srccode   = SourceCode()
		self.done      = done
		self.thread    = threading.Thread(target=_apk_analysis, args=(self,))
		self.thread.start()
