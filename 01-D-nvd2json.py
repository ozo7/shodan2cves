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
import xml.etree.ElementTree as ET  # lxml provides the benefit of being fully compliant with XML standards. It is also extremely fast, and provides support for features such as validation, XSLT, and XPath
#import xmltodict	# needs to be installed, use only for static xml structures
import codecs # todo

# create CVE dictionary

class NVD_Parser():

	def __init__(self, destfolder, sourcefolder):
		self.destfolder = destfolder
		self.sourcefolder = sourcefolder
				
		self.cve_file_prefix = "nvdcve-2.0-"
		self.clean_file_suffix = "-clean.xml"
		self.cve_files = set()				# nvd cve annual files, remove the namespaces in the root tag!
		self.cve_clean_files = set()			# is named based on cve files with renamed file ending.
		self.cpe_file = self.destfolder + "cve-dic.json"
			
		self.cvecpe_file = "official-cpe-dictionary_v2.3.xml"	# nvd cpe dictionary file, remove the namespaces in the root tag!
		self.vendor_file = "vendorstatements.xml"	# vendor statements for cves
		
		self.identify_source_files()		
		print(">>> Initialized.")
		
	def identify_source_files(self):
		folder = self.sourcefolder
		for the_file in os.listdir(folder):			
			file_path = os.path.join(folder, the_file)
			if os.path.isfile(file_path):					
				if the_file[:len(self.cve_file_prefix)] == self.cve_file_prefix:
					self.cve_files.add(the_file)
					print(">>> Found cve source file:", self.sourcefolder + the_file)
				if the_file == self.cvecpe_file:
					print(">>> Found cve cpe dictionary file:", self.sourcefolder + the_file)
				if the_file == self.vendor_file:
					print(">>> Found cve vendor statements file:", self.sourcefolder + the_file)
	
	def identify_cve_clean_files(self):
		folder = self.destfolder
		for the_file in os.listdir(folder):			
			file_path = os.path.join(folder, the_file)
			if os.path.isfile(file_path):					
				if the_file[:len(self.cve_file_prefix)] == self.cve_file_prefix:
					if the_file[-len(self.clean_file_suffix):] == self.clean_file_suffix:
						self.cve_clean_files.add(the_file)
						print(">>> Found cve clean file:", self.destfolder + the_file)
				
	def clean_header(self, inputfile):
		with codecs.open(sourcefolder + inputfile, "r", encoding='utf8') as fin:
			tmpfile = inputfile.replace(".xml", ".tmp")
			with codecs.open(sourcefolder + tmpfile, "w", encoding='utf8') as fout:
				lines = fin.readlines()
				countlines = 1
				for line in lines:
					if countlines == 2:
						match = re.match(r'^<.+?( xmlns:.+?)>', line)
						if match:
							line = re.sub(r"" + match.group(1) + "", r'', line)
						countlines += 1	
					countlines += 1
					fout.write(line)
		# replace the original files by the tmp files:
		os.unlink(sourcefolder + inputfile)
		os.rename(sourcefolder + tmpfile, sourcefolder + inputfile)
	
	def clean_sources(self):
		
		# do it on cve files
		prefixes = ("scap-core", "cvss", "vuln", "patch", "cpe-lang")
		for inputfile in self.cve_files:
			self.clean_header(inputfile)
			self.clean_name_conflicts(inputfile, prefixes)
		# do it on cpe dictionary file
		prefixes = ("scap-core", "config", "xsi", "ns6", "cpe-23", "meta")
		self.clean_header(self.cvecpe_file)
		self.clean_name_conflicts(self.cvecpe_file, prefixes)
		# do it on the vendor file
		prefixes = ("nvd", "xsi")
		self.clean_header(self.vendor_file)
		self.clean_name_conflicts(self.vendor_file, prefixes)	
	
	def clean_name_conflicts(self, inputfile, prefixes):		
		
			print(">>> Clean names of input file:", self.sourcefolder + inputfile)			
			prefixdic = {}
			prefixdic["x"] = set()
			for prefix in prefixes:
				prefixdic[prefix] = set()		
			with codecs.open(self.sourcefolder + inputfile, "r", encoding='utf8') as fin:
				lines = fin.readlines()
				for line in lines:
					#get the normal elements, marked as "x"
					match = re.search(r"</([^:]+)?>", line)
					if match:
						prefixdic["x"].add(match.group(1))
					#get the namespace elements
					for prefix in prefixes:
						match = re.search(r"<" + prefix + ":(.+?)[\s,>]", line)
						if match:
							prefixdic[prefix].add(match.group(1))
			overallset = set()
			
			# find the double, multiple names:
			doubles = set()
			for prefix in prefixdic:
				pprefix = prefixdic[prefix]
				iset = overallset.intersection(pprefix)
				if len(iset) > 0:
					doubles = doubles.union(iset)
					iset = set()
				overallset = overallset.union(pprefix)				
				
				#for pp in pprefix:
				#	print(prefix, pp)
			if len(doubles) > 0:
				print("\t!>> Found mulitple elements: ", str(doubles))
			else:
				print("\t>>> No namespace conflicts found: ", str(doubles))
			
			# now we replace all tags			
			# replace tokens:
			cleanfile = inputfile.replace(".xml","-clean.xml")
			x = "x--"
			token = "--"
			pp = ""
			for p in prefixes:
				pp += r"(?!" + p + r"--)"			
			pat_x_closing_tag = r"</" + pp + "(.+?)>"
			pat_x_opening_tag = r"(?=<[^/,?])<" + pp + "(.+?)>"
			with codecs.open(self.destfolder + cleanfile, "w", encoding='utf8') as fout:
				with codecs.open(self.sourcefolder + inputfile, "r", encoding='utf8') as fin:
					lines = fin.readlines()
					for line in lines:
						# substitute all namespace closing tags
						for prefix in prefixes:
							regex = r"</" + prefix + ":"
							result = re.findall(regex, line)
							for rr in result:
								line = re.sub(regex, rr[:-1] + token, line)
						# substitute all namespace opening tags
						for prefix in prefixes:
							regex = r"<" + prefix + ":"
							result = re.findall(regex, line)
							for rr in result:
								line = re.sub(regex, rr[:-1] + token, line)	
						# substitute all closing tags </something> with </x-something>
						regex = pat_x_closing_tag						
						result = re.findall(regex, line)
						for rr in result:
							line = re.sub(regex, "</" + x + rr + ">", line)
						# substitute all opening tags 
						regex = pat_x_opening_tag
						result = re.findall(regex, line)
						for rr in result:
							line = re.sub(regex, "<" + x + rr + ">", line)
														
						fout.write(line)
			
			print(">>> Clean file produced:", self.destfolder + cleanfile)
				#!! stop, simply try to work with the file removing the namespaces in the header. The tags will remain unique by the prefix!!
				#=> this did not help, the error about unbound namespace still persisted. So this script was completed.
		
	def cves_xmlparse2json(self):	
		
		if len(self.cve_clean_files) == 0:
			self.identify_cve_clean_files()
			if len(self.cve_clean_files) == 0:
				print("!!> Cannot continue. Clean files ending on ", self.clean_file_suffix , "missing in :", self.destfolder)
				return False
		
		for cleanfile in self.cve_clean_files:
			
			tree = ET.parse(self.destfolder + cleanfile)
			root = tree.getroot()
			
			# xml functions cheat sheet:
			# for child in node.iter(nameofmultiplechildnode)			# recursive in node tree
			# for found in root.findall(nameofnodes)					# only direct children
			# for singlefound in root.find(namofnode)					# returns only first found, only direct children
			# Element.text, Element.get()
			
			cvedic = {}
			for entry in root.findall("x--entry"):
				problems = []
				try:				
					cve_id = entry.get("id")
					dtz_published = entry.find("vuln--published-datetime").text
					dtz_last_modified = entry.find("vuln--last-modified-datetime").text
					text = entry.find("vuln--summary").text
					if text[:12] == "** REJECT **":
						is_valid = False				# ! important, we exclude rejected cves
						continue
					else:
						is_valid = True
					cvss = entry.find("vuln--cvss")
					if cvss != None:
						cvss = cvss.find("cvss--base_metrics").find("cvss--score")					# optional
						if cvss != None:						
							cvss = cvss.text						
					cwe = entry.find("vuln--cwe")			# optional
					if cwe != None:
						cwe = cwe.get("id")					
					test_operators = []
					cpes1 = []
					cpes2 = []
					references = []
					node = entry.findall("vuln--vulnerable-configuration")
					if node != None:
						for nnode in node:
							for logical_test in nnode.findall("cpe-lang--logical-test"):
								test_operators.append(logical_test.get("operator"))				
							for cpe1 in nnode.iter("cpe-lang--fact-ref"):
								cpes1.append(cpe1.get("name"))
					else:
						problems.append("no config")
					node = entry.find("vuln--vulnerable-software-list")
					if node != None:
						for cpe2 in node.findall("vuln--product"):
							cpes2.append(cpe2.text)
					else:
						problems.append("no software")
					node = entry.find("vuln--references")
					if node != None:
						for r in node.findall("vuln--reference"):
							references.append(r.text)
					else:
						problems.append("no reference")
					# cve-info
					# diffcount diffset
					s1 = set(cpes1)
					s2 = set(cpes2)
					diffset = s1.difference(s2)
					if not diffset:
						diffset = s2.difference(s1)
					diffcount = len(diffset)
					diffstring = ""
					for element in diffset:
						char = element[5]  # c p e : / X
						diffstring += char				
				except:
					print(traceback.format_exc())
					print("\t !!> error on data spot:\t", cve_id)
					break
				
				cvedic[cve_id] = {}
				cc = cvedic[cve_id]
				cc["dtz_published"] = dtz_published
				cc["dtz_last_modified"] = dtz_last_modified
				cc["text"] = text
				cc["is_valid"] = is_valid
				cc["cvss"] = cvss
				cc["cwe"] = cwe
				cc["test_operators"] = test_operators
				cc["cpes1"] = list(s1)
				cc["cpes2"] = list(s2)
				cc["references"] = references
				cc["diffset"] = list(diffset)
				cc["diffcount"] = diffcount
				cc["diffstring"] = diffstring
				cc["problems"] = problems
			
			cvedicfile = cleanfile.replace("-clean.xml", ".json")
			with codecs.open(self.destfolder + cvedicfile, "w", encoding='utf8') as fout:
				json.dump(cvedic, fout)

			print(">>> json file produced:", cvedicfile)
		return True
	
	def cpes2json(self):
		
		# identify cpe clean file
		cleanfile = self.cvecpe_file.replace(".xml", "-clean.xml")
		folder = self.destfolder
		is_present = False
		for the_file in os.listdir(folder):			
			file_path = os.path.join(folder, the_file)
			if os.path.isfile(file_path):
				if the_file == cleanfile:
					is_present = True
					print(">>> Found cve cpe dictionary clean file:", self.destfolder + the_file)		
		if not is_present:
			print("!!> Cannot continue. Clean file missing:", self.destfolder + cleanfile)
			return False
		
		tree = ET.parse(self.destfolder + cleanfile)
		root = tree.getroot()			
			
		cpedic = {}
		
		for entry in root.findall("x--cpe-item"):
			problems = []
			try:				
				cpe = entry.get("name")
				title = entry.find("x--title").text
				node = entry.find("x--references")
				references = []
				if node != None:
					r = node.findall("x--reference")
					references = []
					for rr in r:
						references.append(rr.get("href"))		
				
			except:
				print(traceback.format_exc())
				print("\t !!> error on data spot:\t", cpe)
				break
			
			cpedic[cpe] = {}
			cc = cpedic[cpe]
			cc["title"] = title				
			cc["references"] = references				
			cc["problems"] = problems
			cc["cves"] = []
		
		cvecpedic_file = self.cvecpe_file.replace(".xml", ".json")
		with codecs.open(self.destfolder + cvecpedic_file, "w", encoding='utf8') as fout:
			json.dump(cpedic, fout)

		print(">>> json file produced:", cvecpedic_file)	
				
	def vendor2json(self):
		
		# identify vendor clean file
		cleanfile = self.vendor_file.replace(".xml", "-clean.xml")
		folder = self.destfolder
		is_present = False
		for the_file in os.listdir(folder):			
			file_path = os.path.join(folder, the_file)
			if os.path.isfile(file_path):
				if the_file == cleanfile:
					is_present = True
					print(">>> Found cve vendor clean file:", self.destfolder + the_file)		
		if not is_present:
			print("!!> Cannot continue. Clean file missing:", self.destfolder + cleanfile)
			return False
		
		tree = ET.parse(self.destfolder + cleanfile)
		root = tree.getroot()			
			
		vendordic = {}
		count = 0		
		for entry in root.findall("nvd--statement"):
			count += 1			
			try:				
				cve = entry.get("cvename")
				organization = entry.get("organization")
				contributor= entry.get("contributor")				
				d_last_modified = entry.get("lastmodified")
				text = entry.text				
				
			except:
				print(traceback.format_exc())
				print("\t !!> error on data spot:\t", cpe)
				break
			
			newentry = []
			newentry.append(organization)
			newentry.append(contributor)
			newentry.append(d_last_modified)
			newentry.append(text)
			
			if cve in vendordic:
				vendordic[cve].append(newentry)				
			else:
				vendordic[cve] = []
				vendordic[cve].append(newentry)			
						
		# consistency check on possibly double cve entries:
		diccount = 0
		for cve in vendordic:
			diccount += len(vendordic[cve])
		diff = count - diccount
		if diff != 0:
			print("!!! Inconsistency in vendor dic: json count differs:", str(diccount), str(count))
		else:
			print("\t>>> json dic count equals xml count.")
		
		vendor_file = self.vendor_file.replace(".xml", ".json")
		with codecs.open(self.destfolder + vendor_file, "w", encoding='utf8') as fout:
			json.dump(vendordic, fout)

		print(">>> json file produced:", vendor_file)
		
try:

	sourcefolder = './source/nvd/'
	destfolder = './meltingpot/'	
	
	# runtime action	
	NVD = NVD_Parser(destfolder, sourcefolder)		#1
	NVD.clean_sources()								#2
	NVD.cves_xmlparse2json()						#3i	independent, if #2 run once, returns boolean on success
	NVD.cpes2json()								#3i independent, pareses the cpe dictionary of the NVD
	NVD.vendor2json()								#3i	vendor statements based on cve

except:
	print(traceback.format_exc())