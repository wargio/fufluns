## fufluns - Copyright 2019-2021 - deroad

from report import BinDetails
from report import Permissions
from report import Issues
from report import SourceCode
from report import Strings
from report import Extra
from report import WebLogger
import importlib
import os
import rzhelp
import rzpipe
import shutil
import tempfile
import threading
import utils
import zipfile

def _cleanup(o, pipe, crashed):
	os.remove(o.filename)
	shutil.rmtree(o.directory)
	if pipe is not None:
		pipe.quit()
	if crashed:
		o.logger.error(">> THE TOOL HAS CRASHED. CHECK THE LOGS <<")
	o.logger.notify("temp files removed, analysis terminated.")


def _ipa_analysis(ipa):
	ipa.logger.notify("opening ipa.")
	try:
		with zipfile.ZipFile(ipa.filename, "r") as zip_ref:
			zip_ref.extractall(ipa.directory)
	except Exception:
		ipa.logger.error("cannot unzip file.")
		_cleanup(ipa, None, False)
		return

	pipe = rzpipe.open("ipa://" + ipa.filename)
	if pipe is None:
		ipa.logger.error("cannot open file.")
		_cleanup(ipa, None, False)
		return

	for file in os.listdir(os.path.join(os.path.dirname(__file__), "tests")):
		if file == "__init__.py" or not file.endswith('.py'):
			continue
		try:
			modpath = 'ios.tests.' + os.path.splitext(file)[0]
			mod = importlib.import_module(modpath)
			ipa.logger.notify(mod.name_test())
			mod.run_tests(ipa, pipe, utils, rzhelp)
		except Exception as e:
			_cleanup(ipa, pipe, True)
			raise e
	_cleanup(ipa, pipe, False)
	ipa.done.set(True)

class Ipa(object):
	"""Ipa class for analysis"""
	def __init__(self, temp_filename, done):
		super(Ipa, self).__init__()
		self.directory = tempfile.mkdtemp()
		self.filename  = temp_filename
		self.logger    = WebLogger()
		self.binary    = BinDetails()
		self.permis    = Permissions()
		self.issues    = Issues()
		self.strings   = Strings()
		self.extra     = Extra()
		self.srccode   = SourceCode()
		self.done      = done
		self.thread    = threading.Thread(target=_ipa_analysis, args=(self,))
		self.thread.start()

