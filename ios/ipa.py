import r2pipe
import r2help
from report import *
import tempfile
import threading
import utils
import os
import shutil
import zipfile
import importlib

def _cleanup(o):
	os.remove(o.filename)
	shutil.rmtree(o.directory)
	o.logger.info("temp files removed, analysis terminated.")


def _ipa_analysis(ipa):
	ipa.logger.info("opening ipa.")
	try:
		with zipfile.ZipFile(ipa.filename, "r") as zip_ref:
			zip_ref.extractall(ipa.directory)
	except Exception:
		ipa.logger.error("cannot unzip file.")
		_cleanup(ipa)
		return

	r2 = r2pipe.open("ipa://" + ipa.filename)
	if r2 is None:
		ipa.logger.error("cannot open file.")
		_cleanup(ipa)
		return

	for file in os.listdir(os.path.join(os.path.dirname(__file__), "tests")):
		if file == "__init__.py" or not file.endswith('.py'):
			continue
		try:
			modpath = 'ios.tests.' + os.path.splitext(file)[0]
			mod = importlib.import_module(modpath)
			ipa.logger.info("#### {} ####".format(mod.name_test()))
			mod.run_tests(ipa, r2, utils, r2help)
		except Exception as e:
			_cleanup(ipa)
			raise e

	_cleanup(ipa)

class Ipa(object):
	"""Ipa class for analysis"""
	def __init__(self, temp_filename):
		super(Ipa, self).__init__()
		self.directory = tempfile.mkdtemp()
		self.filename  = temp_filename
		self.logger    = WebLogger()
		self.binary    = BinDetails()
		self.permis    = Permissions()
		self.issues    = Issues()
		self.thread    = threading.Thread(target=_ipa_analysis, args=(self,))
		self.thread.start()

