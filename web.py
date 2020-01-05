## fufluns - Copyright 2019 - deroad

import os, json
import tornado.ioloop
import tornado.web

WWW_FOLDER=os.path.join(os.path.dirname(os.path.realpath(__file__)), "www")

class ApiHandler(tornado.web.RequestHandler):
	def initialize(self, core):
		self.core = core

	def set_default_headers(self):
		self.set_header('Content-Type', 'application/json')

	def get(self, method):
		if method == "version":
			self.write(json.dumps(self.core.version()))
		elif method == "newsession":
			self.write(json.dumps({"session": self.core.newsession()}))
		elif method.startswith("report/"):
			session_id = method[len("report/"):]
			if len(session_id) < 32:
				self.write(json.dumps({"error": "Session not found."}))
			else:
				session = self.core.getsession(session_id)
				if session is None:
					self.write(json.dumps({"error": "Session not found."}))
				else:
					self.write(session.report())
		else:
			self.write(json.dumps({"error": "Method Not Allowed"}))

	def post(self, method):
		if method.startswith("analyze/"):
			session_id = method[len("analyze/"):]
			if len(session_id) < 32:
				self.write(json.dumps({"error": "Session not found."}))
			else:
				for _, files in self.request.files.items():
					for info in files:
						session = self.core.analyze(session_id, info["filename"], info["body"])
						if session is not None:
							self.write(json.dumps({"error": None}))
						else:
							self.write(message=json.dumps({"error": "Invalid file extension or session."}))
						return
		else:
			self.write(json.dumps({"error": "Method Not Allowed"}))


def make_app(settings, core):
	handlers = [
		(r"/", tornado.web.RedirectHandler, {"url": "/ui/index.html"}),
		(r"/ui", tornado.web.RedirectHandler, {"url": "/ui/index.html"}),
		(r"/ui/", tornado.web.RedirectHandler, {"url": "/ui/index.html"}),
		(r"/ui/(.*)", tornado.web.StaticFileHandler, {'path': WWW_FOLDER}),
		(r"/api", tornado.web.RedirectHandler, {"url": "/api/"}),
		(r"/api/(.*)", ApiHandler, core),
		(r"/(.*)", tornado.web.RedirectHandler, {"url": "/ui/index.html"}),
	]
	return tornado.web.Application(handlers, **settings)

class Server():
	"""Python http server"""
	def __init__(self, core, listen=8080, proto="http"):
		super(Server, self).__init__()
		self.listen  = listen
		self.proto = proto
		self.app = make_app({'debug': True}, dict(core=core))

	def run(self):
		self.app.listen(self.listen)
		print("Server available at {proto}://localhost:{port}".format(proto=self.proto, port=self.listen))
		tornado.ioloop.IOLoop.instance().start()