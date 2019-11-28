# -*- coding: utf-8 -*-
import re
import json
import traceback
#import sys
#import itertools
import os
#import hashlib
#import time
#import shutil
import codecs

# create matcher data structure and store to json file

class NVD():

	def __init__(self, sourcefolder):
		
		self.sourcefolder = sourcefolder
		self.reportfolder = "./reports-99/"
		
		self.cve_file_prefix = "nvdcve-2.0-"
		self.cve_files = set()
		self.cvedics = {}
		self.cvecpe_file = "official-cpe-dictionary_v2.3.json"
		self.cpedic = {}
		self.vendor_file = "vendorstatements.json"
		self.vendordic = {}
		self.invalid_cves = {}
		
		self.sep = "~"

		self.cpe3_matcher_file = "cpe3-matcher.json"
		
		self.identify_source_files()		
		print(">>> Initialized.")
		
	def identify_source_files(self):
		folder = self.sourcefolder
		for the_file in os.listdir(folder):			
			file_path = os.path.join(folder, the_file)
			if os.path.isfile(file_path):
				print
				if the_file[-5:] == ".json":
					if the_file[:len(self.cve_file_prefix)] == self.cve_file_prefix:
						self.cve_files.add(the_file)
						print(">>> Found cve source file:", self.sourcefolder + the_file)
					if the_file == self.cvecpe_file:
						print(">>> Found cve cpe dictionary file:", self.sourcefolder + the_file)
					if the_file == self.vendor_file:
						print(">>> Found cve vendor statements file:", self.sourcefolder + the_file)
						
	def load_all(self):
		for inputfile in self.cve_files:
			year = re.match(r"" + self.cve_file_prefix + r"(\d\d\d\d)", inputfile)
			if not year:
				print("!!> Problem matching file name parsing, please check:", self.sourcefolder + inputfile)
				raise "!!> Problem matching file name parsing, please check:" + self.sourcefolder + inputfile
			with codecs.open(self.sourcefolder + inputfile, "r", encoding="utf-8") as fin:
				mydic = json.load(fin)				
				self.cvedics[year.group(1)] = mydic
		with codecs.open(self.sourcefolder + self.cvecpe_file, "r", encoding="utf-8") as fin:
				self.cpedic = json.load(fin)
		with codecs.open(self.sourcefolder + self.vendor_file, "r", encoding="utf-8") as fin:
				self.vendordic = json.load(fin)
		print(">>> json absorbed in memory.")	
		
	def cve_checks(self):
		
		#cve = self.cvedic["CVE-2015-4257"]
		#print(json.dumps(cve,indent=4))
		print(">>> Starting checks.")
		outputfile = "zz-cve-checks.txt"
		with codecs.open(self.reportfolder + outputfile, "w", encoding="utf-8") as fout:
			fout.write("Checks on annual CVE dictionaries:" + "\n")
			fout.write("=="*30 + "\n")
		
			# check for invalid cves
			for cyear in self.cvedics:
				cvedic = self.cvedics[cyear]
				for cve in cvedic:
					cc = cvedic[cve]			
					if not cc["is_valid"]:
						fout.write(cve + "!!! <<< This here should not happen as there are supposed to be no invalid cves transferred to the json dic")
			fout.write("=="*30 + "\n")
				
			# count the cvss information				
			for cyear in self.cvedics:
				cvss_count = 0
				cvss_average = 0
				total = 0	
				fout.write(">>> CVE count for " + cyear + "\n")
				cvedic = self.cvedics[cyear]
				for cve in cvedic:
					try:
						cc = cvedic[cve]
						total += 1
						if cc["cvss"]:					
							cvss_count += 1
							cvss_average += float(cc["cvss"])
					except:
						print(traceback.format_exc())
						print("data spot:", cve)
						break
				cvss_average = cvss_average / cvss_count
				fout.write(">>> CVE count " + str(cvss_count) + " of total # " + str(total) + ", average CVSS: " + str(cvss_average) + "\n")
				fout.write("=="*30 + "\n")
				
			# report on missing data			
			for cyear in self.cvedics:
				ccount = 0
				total = 0
				marked_invalid = 0
				fout.write(">>> Missing data for " + cyear + "\n")
				cvedic = self.cvedics[cyear]
				for cve in cvedic:
					try:
						cc = cvedic[cve]
						total += 1
						if cc["problems"]:					
							ccount += 1
							fout.write(cve + str(cc["problems"]) + "\n")
							if "no config" in cc["problems"]:
								cc["is_invalid"] = True			# we cannot use a cve without any cpe in later processing.
								self.invalid_cves[cve] = cc.copy()	# we take it to a separete dictionary								
								marked_invalid += 1
					except:
						print(traceback.format_exc())
						print("data spot:", cve)
						break
				cvss_average = cvss_average / cvss_count
				fout.write(">>> problem count " + str(ccount) + " of total # " + str(total) + "\n")
				fout.write(">>> CVEs marked as invalid: " + str(marked_invalid) + "\n")
				fout.write("=="*30 + "\n")
			
			# report on cve differences			
			for cyear in self.cvedics:
				ccount = 0
				total = 0
				fout.write(">>> CVE group differences for " + cyear + "\n")
				cvedic = self.cvedics[cyear]
				for cve in cvedic:
					try:
						cc = cvedic[cve]
						total += 1
						if int(cc["diffcount"]) != 0:				
							ccount += 1
							fout.write(cve + "---" + str(cc["diffcount"]) + "---" + str(cc["diffstring"]) + "\n")
					except:
						print(traceback.format_exc())
						print("data spot:", cve)
						break
				cvss_average = cvss_average / cvss_count
				fout.write(">>> cve diff count " + str(ccount) + " of total # " + str(total) + "\n")
				fout.write("=="*30 + "\n")
			
			# let us remove the invalid cves for not disturbing future analysis.
			for icve in self.invalid_cves:
				cyear = icve[4:8]
				del self.cvedics[cyear][icve]
			fout.write("!>> " + str(len(self.invalid_cves)) + " invalid cves found before were removed from cve dictionary " + cyear + "\n")
			fout.write("=="*30 + "\n")
		print(">>> Check result written to:" + self.reportfolder + outputfile)
	
	def update_cpedic(self):
		# update cpe dictionary and see how cpes fit
		print(">>> Starting cve in dictionary plain check.")
		outputfile = "zz-cpe-in-dic-check.txt"
		with codecs.open(self.reportfolder + outputfile, "w", encoding="utf-8") as fout:
			fout.write("Checks on cve in dictionaries:" + "\n")
			fout.write("=="*30 + "\n")
			for cyear in self.cvedics:
				try:
					miss_count = 0
					fout.write(">>> Checking cpe dic with cves of :" + cyear + "\n")
					cvedic = self.cvedics[cyear]
					missing_cpes = set()
					cves_with_miss = set()
					for cve in cvedic:
						cc = cvedic[cve]
						for cpe in cc["cpes1"]:	# we take the first group that contains more than the second					
							if cpe in self.cpedic:
								if not cpe in self.cpedic[cpe]["cves"]:	# keeping it clean like a set
									self.cpedic[cpe]["cves"].append(cpe)
							else:						
								missing_cpes.add(cpe)
								cves_with_miss.add(cve)
					miss_count = len(missing_cpes)
					if miss_count > 0:
						fout.write("!>> " + str(miss_count) + " missing cpes in dic for year :" + cyear + "\n")
					fout.write("=="*30 + "\n")
					for cpe in missing_cpes:
						fout.write(cpe + "\n")
					fout.write("=="*30 + "\n")
				except:
					print(traceback.format_exc())
					print("data spot:", cve)
					break
		# it seems that the dictionary cannot add much value.
	
	def create_cpe3_matcher(self):
		# ignore the dictionary, just take real cpes that match to a cve
		# the matcher is to join all cpes-cve combinations to a 3-level cpe			
		
		level2 = {}
		pat_3 = re.compile(r"(cpe:/.:.+?:.+?)(:|$)")
		cpe3_matcher = {}
		for cyear in self.cvedics:
			print(">>> Starting 3-level cpe-cve dictionary creation for year: " + cyear)	
			try:
				cvedic = self.cvedics[cyear]
				for cve in cvedic:
					cc = cvedic[cve]
					for cpe in cc["cpes1"]:	# we take the first group that contains more than the second					
						if cpe.count(":") < 3:  # report cves containing a 2-level cpe
							level2[cve] = cc.copy()
							print("\t!>> Found 2-level cpe: " + cpe + " in " + cve)
						else:
						# put into 3-level cpe structure, our cpe3-matcher
							match = re.match(pat_3, cpe)
							cpe3 = match.group(1)
							if cpe3 in cpe3_matcher:
								ccpe3 = cpe3_matcher[cpe3]
							else:
								cpe3_matcher[cpe3] = {}
								ccpe3 = cpe3_matcher[cpe3]							
							if cve in ccpe3:
								if cpe not in ccpe3[cve]:
									ccpe3[cve].append(cpe)	
							else:
								ccpe3[cve] = []		# we count cpe3 in ranking by cve occurence
								ccpe3[cve].append(cpe)						
							
				print(">>> Finished 3-level cpe-cve dictionary creation for year: " + cyear)			
			except:
				print(traceback.format_exc())
				print("data spot:", cve)
				break
				
			# create a ranking of cpe3 occurence
			cpe3_ranking = sorted(cpe3_matcher, key=lambda x : len(cpe3_matcher[x]), reverse=True) 
			
			#for ccpe3 in sorted(cpe3_matcher, key=ccpe3.get["count"], reverse=True):
			#	print(ccpe3 + self.sep + str(cpe3_matcher[ccpe3]["count"]) + "\n")
			outputfile = "zz-cpe3-ranking-" + cyear + ".txt"
			with codecs.open(self.reportfolder + outputfile, "w", encoding="utf-8") as fout:
				for cpe3 in cpe3_ranking:
					fout.write(str(len(cpe3_matcher[cpe3])) + self.sep + cpe3 + "\n")
				print(">>> Created cpe3-ranking for year: " + cyear)		
			
			# save the cpe3-matcher to disk
			with codecs.open(self.sourcefolder + self.cpe3_matcher_file, "w", encoding="utf-8") as fout:
				json.dump(cpe3_matcher, fout)
			print(">>> cpe3-matcher saved in json file: " + self.sourcefolder + self.cpe3_matcher_file)	
	
	# manual check on cve in cve dictionary
	def print_cve(self, cve):
		cyear = cve[4:8]
		cvedic = self.cvedics[cyear]
		cc = cvedic[cve]
		print(json.dumps(cc, indent=4))
				
		

	######################################################################################
	#	json dictionary cheat sheets:
	#	## annual cves					## cpe dictionary		## vendor statements		## *cpe matcher
	#	##key: cve						## key: cpe				## key: cve					## key: 3-level cpe
	#	cc["dtz_published"]				cc["title"]				[organization,				#  cpe3[cve] => [] of cpes
	#	cc["dtz_last_modified"]			cc["references"]		contributor,				
	#	cc["text"]						cc["problems"]			d_last_modified,
	#	cc["is_valid"]					*cc["cves"]				text]
	#	cc["cvss"]												
	#	cc["cwe"]												
	#	cc["test_operators"]			
	#	cc["cpes1"]						
	#	cc["cpes2"]						
	#	cc["references"]				
	#	cc["diffset"]
	#	cc["diffcount"]
	#	cc["diffstring"]
	#	cc["problems"]
	######################################################################################
try:

	sourcefolder = './meltingpot/'	
	
	# runtime action
	NVD = NVD(sourcefolder)					#1
	NVD.load_all()							#2		loads all json files into memory	
	NVD.cve_checks()							#3		does some checks on the data and reports to file
	NVD.update_cpedic()						#3		reports on missing cves in cve dictionary, plain comparison
	NVD.create_cpe3_matcher()				#3		creates cpe3-dictionary on level cpe:/[partition:[hardware|os|application]]/[product]/[version]	
	
	#NVD.print_cve("CVE-2014-8439")			#3		manual cve output

except:
	print(traceback.format_exc())