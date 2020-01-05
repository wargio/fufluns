## fufluns - Copyright 2019 - deroad

import subprocess
import re

def _exec(cmd):
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True)
	(stdout, junk) = p.communicate()
	p.wait()
	return stdout.decode('utf-8').strip()

def radare2():
	ver = _exec("radare2 -v")
	find = re.findall(r'radare2 ([\d\.]+(-git)?)|([\da-fA-F]{40})', ver, re.M)
	return "{version} {commit}".format(version=find[0][0], commit=find[1][2])

def apkid():
	ver = _exec("apkid")
	find = re.search(r'[\d\.]{5}', ver)
	return find.group()

def apktool():
	return _exec("apktool -version")
