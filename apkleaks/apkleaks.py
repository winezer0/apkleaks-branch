#!/usr/bin/env python3
import io
import json
import logging.config
import os
import re
import shutil
import sys
import tempfile
import threading
import time

from contextlib import closing
from shutil import which
from pathlib import Path
from pipes import quote
from urllib.request import urlopen
from zipfile import ZipFile

from pyaxmlparser import APK

from apkleaks.colors import color as col
from apkleaks.utils import util

class APKLeaks:
	def __init__(self, args):
		self.apk = None
		self.file = os.path.realpath(args.file)
		self.json = args.json
		self.disarg = args.args
		self.clear = args.clear

		self.prefix = "apkleaks"
		self.tempdir_ = os.path.join(os.getcwd(), f"{self.prefix}-out", f"{os.path.basename(args.file)}")
		self.tempdir = os.path.join(os.getcwd(), f"{self.prefix}-out", f"{os.path.basename(args.file)}")
		self.main_dir = os.path.dirname(os.path.realpath(__file__))

		self.output = os.path.join(os.getcwd(), f"{self.prefix}-out", "result.txt") if args.output is None else args.output
		if not os.path.exists(os.path.dirname(self.output)):
			os.makedirs(os.path.dirname(self.output))
		self.output_json = self.output + ".json"
		self.output_open = open(self.output, "a+")

		self.pattern = os.path.join(str(Path(self.main_dir).parent), "config", "regexes.json") if args.pattern is None else args.pattern
		self.jadx = which("jadx") if which("jadx") is not None else os.path.join(str(Path(self.main_dir).parent), "jadx", "bin", "jadx%s" % (".bat" if os.name == "nt" else "")).replace("\\","/")
		self.out_json = {}
		self.scanned = False
		logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})

	def apk_info(self):
		return APK(self.file)

	def dependencies(self):
		exter = "https://github.com/skylot/jadx/releases/download/v1.2.0/jadx-1.2.0.zip"
		try:
			with closing(urlopen(exter)) as jadx:
				with ZipFile(io.BytesIO(jadx.read())) as zfile:
					zfile.extractall(os.path.join(str(Path(self.main_dir).parent), "jadx"))
			os.chmod(self.jadx, 33268)
		except Exception as error:
			util.writeln(str(error), col.WARNING)
			sys.exit()

	def integrity(self):
		if os.path.exists(self.jadx) is False:
			util.writeln("Can't find jadx binary.", col.WARNING)
			valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
			while True:
				util.write("Do you want to download jadx? (Y/n) ", col.OKBLUE)
				try:
					choice = input().lower()
					if choice == "":
						choice = valid["y"]
						break
					elif choice in valid:
						choice = valid[choice]
						break
					else:
						util.writeln("\nPlease respond with 'yes' or 'no' (or 'y' or 'n').", col.WARNING)
				except KeyboardInterrupt:
					sys.exit(util.writeln("\n** Interrupted. Aborting.", col.FAIL))
			if choice:
				util.writeln("\n** Downloading jadx...\n", col.OKBLUE)
				self.dependencies()
			else:
				sys.exit(util.writeln("\n** Aborted.", col.FAIL))
		if os.path.isfile(self.file):
			try:
				self.apk = self.apk_info()
			except Exception as error:
				util.writeln(str(error), col.WARNING)
				sys.exit()
			else:
				return self.apk
		else:
			sys.exit(util.writeln("It's not a valid file!", col.WARNING))

	def decompile(self):
		util.writeln("** Decompiling APK...", col.OKBLUE)

		print("%s** Decompiling Temp Dir '%s%s%s%s'%s." % (col.HEADER, col.ENDC, col.OKGREEN, self.tempdir, col.HEADER, col.ENDC))

		if os.path.exists(self.tempdir) and not self.clear:
			util.writeln("** Decompiling APK History Exists, Skip... ", col.FAIL)
			return

		args = [self.jadx, self.file, "-d", self.tempdir]
		try:
			args.extend(re.split(r"\s|=", self.disarg))
		except Exception:
			pass
		comm = "%s" % (" ".join(quote(arg) for arg in args))
		comm = comm.replace("\'","\"")
		print("%s\n** os.system '%s%s%s%s'%s." % (col.HEADER, col.ENDC, col.OKGREEN, comm, col.HEADER, col.ENDC))
		os.system(comm)

	def extract(self, name, matches):
		if len(matches):
			stdout = ("[%s]" % (name))
			util.writeln("\n" + stdout, col.OKGREEN)
			self.output_open.write("%s" % (stdout + "\n"))
			for secret in matches:
				if name == "LinkFinder":
					if re.match(r"^.(L[a-z]|application|audio|fonts|image|kotlin|layout|multipart|plain|text|video).*\/.+", secret) is not None:
						continue
					secret = secret[len("'"):-len("'")]
				stdout = ("- %s" % (secret))
				print(stdout)
				self.output_open.write("%s" % (stdout + "\n"))
			self.output_open.write("%s" % "\n")
			self.out_json["results"].append({"name": name, "matches": matches})
			self.scanned = True

	def scanning(self):
		if self.apk is None:
			sys.exit(util.writeln("** Undefined package. Exit!", col.FAIL))
		util.writeln("\n** Scanning against '%s'" % (self.apk.package), col.OKBLUE)
		self.out_json["package"] = self.apk.package
		self.out_json["results"] = []
		with open(self.pattern) as regexes:
			regex = json.load(regexes)
			for name, pattern in regex.items():
				if isinstance(pattern, list):
					for p in pattern:
						try:
							thread = threading.Thread(target = self.extract, args = (name, util.finder(p, self.tempdir)))
							thread.start()
						except KeyboardInterrupt:
							sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))
				else:
					try:
						thread = threading.Thread(target = self.extract, args = (name, util.finder(pattern, self.tempdir)))
						thread.start()
					except KeyboardInterrupt:
						sys.exit(util.writeln("\n** Interrupted. Aborting...", col.FAIL))

	def cleanup(self):
		if self.clear:
			shutil.rmtree(self.tempdir)
		if self.scanned:
			time.sleep(1)
			print("\n%s** Results saved into '%s%s%s%s'%s." % (col.HEADER, col.ENDC, col.OKGREEN, self.output, col.HEADER, col.ENDC))
			if self.json:
				with open(self.output_json, "w+") as f_open:
					json.dump(self.out_json, f_open, indent=4)
				print("%s** Json Results saved into '%s%s%s%s'%s." % (col.HEADER, col.ENDC, col.OKGREEN, self.output_json, col.HEADER, col.ENDC))
		else:
			os.remove(self.output)
			util.writeln("\n** Done with nothing. ¯\\_(ツ)_/¯", col.WARNING)

		self.output_open.close()
