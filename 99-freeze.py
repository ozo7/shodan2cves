# -*- coding: utf-8 -*-
import traceback
import os
import sys
import shutil
import json

# creates a backup of all data of a CPE2Banner stage.

def copytree(src, dst, symlinks=False, ignore=None):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, symlinks, ignore)
        else:
            shutil.copy2(s, d)

def user_interaction():
	freeze_file = "./zz-info/freezestage.txt"
	if not os.path.exists(freeze_file):
		default = 99
		user_input = input("Please enter the freeze stage: %s"%default + chr(8)*2)
		user_input = user_input or 99
		with open(freeze_file, "w") as fout:
			json.dump(int(user_input), fout)
		freezestage = int(user_input)
	else:
		with open(freeze_file, "r") as fin:
			freezestage = json.load(fin)		
	sourcedirs = ("meltingpot", "probe-prepare", "probing", "shodan-download", "reports-99", "source")
	archivedir = "./zz-archive/freeze-" + "{0:0=2d}".format(freezestage)
	if os.path.exists(archivedir):
		print("!!! Abort, destination folder already exists.")
		sys.exit(0)
	else:
		os.makedirs(archivedir)
		for d in sourcedirs:
			newdir = archivedir + "/" + d
			os.makedirs(newdir)
			copytree(d, newdir)
		shutil.make_archive(archivedir, 'zip', archivedir)
		shutil.rmtree(archivedir)
		with open(freeze_file, "w") as fin:
			freezestage += 1
			json.dump(freezestage, fin)			

try:
	
	user_interaction()
	
except:
	print(traceback.format_exc())