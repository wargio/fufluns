import r2pipe
import report
import threading

def _apk_analysis(apk):
	apk.logger.info("opening apk.")
	r2 = r2pipe.open("apk://" + apk.filename)
	if r2 is None:
		apk.logger.error("cannot open file.")
		return

class Apk(object):
	"""Apk class for analysis"""
	def __init__(self, temp_filename):
		super(Apk, self).__init__()
		self.filename = temp_filename
		self.thread   = None
		self.logger   = report.WebLogger()
		self.binary   = report.BinDetails()
		self.permis   = report.Permissions()
		self.issues   = report.Issues()

	def start(self):
		if self.thread is None:
			self.thread  = threading.Thread(target=_apk_analysis, args=(self,))
			self.thread.start()