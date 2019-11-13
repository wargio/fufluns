import sys
import web
from core import Core

def main(argc, argv):
	core = Core()
	server = web.Server(core)
	server.run()

if __name__ == '__main__':
	main(len(sys.argv), sys.argv)