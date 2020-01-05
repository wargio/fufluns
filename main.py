## fufluns - Copyright 2019 - deroad

import sys
import web
from core import Core

def main(argc, argv):
	core = Core()
	port = 8080
	if argc > 1:
		if argv[1] == '-h' or argv[1] == '--help':
			print("usage:  {} <port>".format(argv[0]))
			sys.exit(0)
		port = int(argv[1])
	server = web.Server(core, port)
	try:
		server.run()
	except KeyboardInterrupt:
		pass

if __name__ == '__main__':
	main(len(sys.argv), sys.argv)