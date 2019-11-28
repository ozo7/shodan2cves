# -*- coding: utf-8 -*-
import re
import json
import traceback
import os
import sys
import hashlib
import codecs

#- Shoot the nmap probe regex against the banners

class Probing():

# preconditions:
# - portmapper file in source, banner file in workfolder, probes file in probe
# in-run:
# - 
# postconditions:
#	 => reports in report

	def __init__(self):
		self.sourcefolder = "./source/"
		self.workfolder = "./probing/"
		self.workfolder2 = "./meltingpot/"
		self.probefolder = "./probe-prepare/"
		self.reportfolder = "./reports-99/"
		
		self.sep = "~"
		self.sep3 = "~~~"
		self.pat_mask = re.compile(r'\r\n')
		
		self.banner_dictionary_file = self.workfolder + "dic-banners.json"
		self.probes_json_file = self.probefolder + "cpe-probes.json"		
		self.portmap_file = self.sourcefolder + "nmap-servicename2port.json"
		
		self.hits_file = self.workfolder2 + "hits.json"
		self.scope_report_file = self.reportfolder + "scope-report.txt"
		self.probes_overview_file = self.reportfolder + "probes-overview.csv"
		self.banners_overview_file = self.reportfolder + "banners-overview.csv"
		self.shodan_cpes_present_file = self.reportfolder + "shodan-cpes-present.csv"
		self.shodan_cpes_not_present_file = self.reportfolder + "shodan-cpes-not-present.csv"
		self.probes_hit_banners_file = self.reportfolder + "probes-hit-banners.csv"
		self.shodan_cpes_not_found_file = self.reportfolder + "shodan-cpes-not-found.csv"
		self.shodan_cpes_not_found_file_2 = self.reportfolder + "shodan-cpes-not-found-2.txt"
		
		#self._incomplete_hits_file = self.reportfolder + "hits_incomplete.json"
		
		self.portmapper = {}
		self.subdirs = () # if there is only one element, have a trailing ,
		self.probedic = {}
		self.bannerdic = {} 
		self.hits = {}	# hits, this is the results we want, especially by cpe. hits are keyed by banner hash
		#self.incomplete_hits = [] # hits whose cpes contain a placeholder $
		# result lists:		
		self.shodan_cpes_present = []	# cpe present, probehash, bannerhash
		self.shodan_cpes_not_present = [] # cpe not present, probehash, bannerhash
		self.probes_hit_banners = []	# probehash, bannerhash		# check double hits
		self.shodan_cpes_not_found = []	# cpe, bannerhash
		self.scope_report = {}			# # By port: tries to hit, actual hits, number probes, number banners
		
		self.problems = []				# description, data spot
		self.bannerdic2 = {} # testing help only
		self.probedic2 = {} # testing help only		
		
		self.checkdestfolder()
		self.load_portmapper()		
		self.load_probedic()
		self.load_bannerdic()
		self.prepare_scope_report()
		print(">>> Probes, banners and portfile initialized.")
		
	def checkdestfolder(self):
		if not os.path.exists(self.workfolder):
			os.makedirs(self.workfolder)
		for subdir in self.subdirs:
			directory = workfolder + subdir
			if not os.path.exists(directory):
				os.makedirs(directory)
				
	def cleanupfiles(self): # check: only subdirectories?
		for subdir in self.subdirs:
			folder = self.workfolder + subdir
			for the_file in os.listdir(folder):
				file_path = os.path.join(folder, the_file)
				try:
					if os.path.isfile(file_path):
						os.unlink(file_path)
					#elif os.path.isdir(file_path): shutil.rmtree(file_path) # traverses also subdirectories
				except Exception as e:
					print (e)
					
	def inform_problems(self):
		if not self.problems:
			print("No logical problems stated. Nice.")
		else:
			print("There are logical problems: ")
			for problem in self.problems:
				print(str(problem))		
	
	def replace_eols(self, string):
		string = string.replace('\r','---r---')
		string = string.replace('\n','---n---')
		return string
	
	def load_probedic(self):
		with codecs.open(self.probes_json_file, "r", encoding="utf-8") as fin:
			self.probedic = json.load(fin)	
	
	def load_bannerdic(self):
		with codecs.open(self.banner_dictionary_file, "r", encoding="utf-8") as fin:
			self.bannerdic = json.load(fin)
			
	def load_portmapper(self):
		with codecs.open(self.portmap_file, 'r', encoding="utf-8") as infile:
			self.portmapper = json.load(infile)
			
	def prepare_scope_report(self):
		# use the portmapper info file		
		for servicename in self.portmapper:
			portnr = self.portmapper[servicename]
			for pportnr in portnr:				
				if not pportnr in self.scope_report:
					self.scope_report[pportnr] = [0,0,0,0] # By port: tries to hit, actual hits, number probes, number banners
		self.scope_report[0] = [0,0,0,0]	# for non-port-based probing
		# counting probes per port		
		for probe in self.probedic:			
			pprobe = self.probedic[probe]
			for port in pprobe["ports"]:				
				if port in self.scope_report:
					self.scope_report[port][2] += 1
		# counting banners per port
		for banner in self.bannerdic:
			bbanner = self.bannerdic[banner]
			for port in bbanner["ports"]:	
				if port in self.scope_report:
					self.scope_report[port][3] += 1
		print(">>> port configuration read from portfile.")
					
	def probing(self, banner, probe, hit):
		# python versus perl regex:
		# OK --  /i is r"(?i)somefurtherregex", ^ is re.match , otherwise re.search, $ is the same
		# OK -- dot matches also new line: /s => (?s), multiline: /m => (?s), freespacing: /x => (?x)
		# OK -- Backreferences: you get them with regexresult.group(1) etc., group(0) is the complete match. Tricky checks to make $1 etc. work.
		# OK -- non-capturing groups: the first group starts with .group(1)
		# ?? -- sometimes \r in regex does prevent from matching
		# ?? -- some probes use $SUBST for substitution in attributes		
		
		bannertext = banner["banner"]
		regex = probe["regex"]
		postfix = probe["postfix"]
		
		is_hit = False
		try:
			regexflags = ""
			if postfix == "i":
				regexflags += "(?i)"		# case insensitive
			if postfix == "s":
				regexflags += "(?s)"		# dot matches new lines also
			if postfix == "m":
				regexflags += "(?m)"		# multiline
			if postfix == "x":
				regexflags += "(?x)"		# free spacing
			if regex[0] == '^':		# match from the beginning in python is re.match, otherwise re.search
				regex = regex[1:]
				xx_regexx = r"" + regexflags + regex + r""
				is_hit = re.match(xx_regexx, bannertext)
			else:
				xx_regexx = r"" + regexflags + regex + r""
				is_hit = re.search(xx_regexx, bannertext)		
			
			# consider Backreferences to adjust the cpes, version, information, product or os hit attributes
			# there are probes using up to $9 !
			if is_hit:
				hit["count"] += 1
				if hit["count"] > 1:
					# there was already a hit, check if this probe is equal or more detailed in cpe					
					for cpe in probe["cpe"]:
						for hcpe in hit["cpe"]:
							# we only want to compare equal cpes that is of both a, o or h cpe:/X
							# and we only accept probes that get better levels, or the chance to remove a $ placeholder
							if cpe[5] == hcpe[5]:								
								cpe_count = cpe.count(":")
								hcpe_count = hcpe.count(":")
								if cpe_count < hcpe_count:
									return (False, hit)				
								if cpe_count == hcpe_count:
									if not '$' in hcpe:
										return (False, hit)	
								# so these checks refuse any probe that potentially lowers the cpe detail.
								# however, it is possible that a probe is refused that lowers one cpe but raises the second.
				# probe, banner, ports, ips, attributes below, especially cpe
				hit["probe"] = probe["hash"]				
				for probeattribute in ("version", "i", "product", "cpe", "os"):
					hit[probeattribute] = probe[probeattribute]
				collector = {}
				for probeattribute in ("version", "i", "product", "cpe", "os"):
						collector[probeattribute] = []
				highest = 0
				for i in range(1,10): # from 1 up to 10, but not including 10
					regex = "\$" + str(i)
					for probeattribute in ("version", "i", "product", "cpe", "os"):						
						if probe[probeattribute]:
							#cpes are lists
							if probeattribute == "cpe":
								for cpe in probe[probeattribute]:
									
									found = re.search(r"" + regex + r"", cpe)
									# print(">>> regex:", regex, "cpe:" , cpe, "found:", found)
									if found:
										collector[probeattribute].append(i)
										#print(">>> found collectorattribute:", str(collector[probeattribute]), "for probe", probe)
										highest = i
							else:
								found = re.search(r"" + regex + r"", str(probe[probeattribute]))
								if found:
									collector[probeattribute].append(i)
									highest = i
				if highest != is_hit.lastindex:
					self.problems.append("!!! Backreferences do not match in Probe attributes, probe id: " + probe["hash"])					
				else:
					# print("Result $ collector:", json.dumps(collector, indent=4))
					# collect the dollars
					
					for probeattribute in ("version", "i", "product", "cpe", "os"):
						# print(">>> \t collectorattribute:", probeattribute, str(collector[probeattribute]))
						for i in collector[probeattribute]:
							
							regex = "\$" + str(i)
							if probeattribute == "cpe":
								hit[probeattribute] = []
								for j in range(0, len(probe[probeattribute])):
									# print("\t Before:", str(self.probedic[probe][probeattribute][j]))
									# print("\t regex:", regex, "2nd:", is_hit.group(i), "third:", str(self.probedic[probe][probeattribute]) )
									xx_regexx = r"" + regex + r""
									substitute = re.sub(xx_regexx, is_hit.group(i), str(probe[probeattribute][j]))
									hit[probeattribute].append(substitute)									
									# print("\t After:", substitute)
							else:
								# print("\t Before:", str(self.probedic[probe][probeattribute]))
								# print("\t regex:", regex, "2nd:", is_hit.group(i), "third:", str(self.probedic[probe][probeattribute]) )
								# print("\t type: ", type(is_hit.group(i)))
								xx_regexx = r"" + regex + r""
								substitute = re.sub(xx_regexx, is_hit.group(i), str(probe[probeattribute]))
								hit[probeattribute] = substitute								
								# print("\t After:", substitute)			 
		except:
			print(traceback.format_exc())
			print("!!! Regex handling, probe id: ", probe["hash"])			
				
		return (is_hit, hit)
	
	
	def test(self):
		
		print(">>> Probing start...")
		# a progress bar, title part
		max = len(self.bannerdic)
		print ('\t>>> Maximum banners to probe:\t',max)
		c = 1
		sys.stdout.write('\r')
		
		for banner in self.bannerdic:
			# a progress bar, cycle part
			sys.stdout.write('\r')
			part = c * 50 // max # max -1 if index is 0 and not 1
			sys.stdout.write("[%-50s] %d%%" % ('='*part, c*100//max))
			sys.stdout.flush()
			c += 1			
			
			bbanner = self.bannerdic[banner]
			shodan_cpe_present = False
			is_hit = False
			hit = {}	# each banner is to have only one hit result
			hit["count"] = 0
			hit["banner"] = bbanner["hash"]
			hit["ports"] = bbanner["ports"]
			hit["ips"] = bbanner["ips"]
			if bbanner["shodan-cpes"]:
				shodan_cpe_present = True
				shodan_cpes = []
				shodan_cpes = bbanner["shodan-cpes"]
			for probe in self.probedic:
				pprobe = self.probedic[probe]				
				# let us check only matching ports
				for pport in bbanner["ports"]: # we have consolidated banners, merged if they happend on more than one port
					# skip the probe - port if it already hit on another port with identical banner
					if probe in hit:
						continue
					if pport in pprobe["ports"]:						
						# a probe is trying to hit on a banner of a certain port
						self.scope_report[pport][0] += 1
						try:
							is_hit, hit = self.probing(bbanner, pprobe, hit)
						except:
							print(traceback.format_exc())
							print("!!! Data spot of banner and probe: ", banner, probe)
							break
						if is_hit: # what are hits here? it is not every probe that matches, but any first one, pluse incrementally better ones later.
							# record the hit
							# put the hit to the hits
							self.hits[hit["banner"]] = hit	
							self.scope_report[pport][1] += 1
							newentry = [] # put probehash, bannerhash
							newentry.append(probe)
							newentry.append(banner)
							self.probes_hit_banners.append(newentry)
							# check if cpe is in shodan-cpes list for banner
							for hcpe in hit["cpe"]:
								if hcpe in shodan_cpes:
									shodan_cpes.remove(hcpe)
									newentry = [] # put cpe present, probehash, bannerhash
									newentry.append(hcpe)
									newentry.append(probe)
									newentry.append(banner)
									self.shodan_cpes_present.append(newentry)
								else:
									# check if it is really not present, it could be just too less specified, a too short cpe:
									is_short = False
									for scpe in bbanner["shodan-cpes"]:
										if hcpe == scpe[:len(hcpe)]:											
											is_short = True
									if not is_short:
										newentry = [] # put cpe not present, probehash, bannerhash
										newentry.append(hcpe)
										newentry.append(probe)
										newentry.append(banner)
										self.shodan_cpes_not_present.append(newentry)
							
							# record the probe in the banner and vice versa
							bbanner["probe-hitlist"].append(probe)
							pprobe["banner-hitlist"].append(banner)
		
			if shodan_cpe_present:
				for scpe in shodan_cpes:
					newentry = [] # put ports, cpe, bannerhash
					newentry.append(bbanner["ports"])	
					newentry.append(scpe)		
					newentry.append(banner)
					self.shodan_cpes_not_found.append(newentry)
		
		print(">>> Probing finished, writing results to files ... ")		
		# after probing here, this is testing control
			#
		
		# Hits
		with codecs.open(self.hits_file, "w", encoding="utf-8") as fout:
			for hit in self.hits:
				hhit = self.hits[hit]
				json.dump(hhit, fout)
				fout.write("\n")
		print(">>> Hits saved to ", self.hits_file)	
		
		# produce a report to regex overview with hit count, and with probe attributes for backreference checks
		with codecs.open(self.probes_overview_file, "w", encoding="utf-8") as fout:
			fout.write("hits~probe hash~version~cpe~info~product~os~regex\n")
			for probe in self.probedic:
				outstring = str(len(self.probedic[probe]["banner-hitlist"])) + self.sep + str(probe) + self.sep + str(self.probedic[probe]["version"]) + self.sep + str(self.probedic[probe]["cpe"]) + self.sep + str(self.probedic[probe]["i"]) + self.sep + str(self.probedic[probe]["product"]) + self.sep + str(self.probedic[probe]["os"]) + self.sep + self.probedic[probe]["regex"] + "\n"
				fout.write(outstring)			
		# then a hash to banner overview with hit count
		with codecs.open(self.banners_overview_file, "w", encoding="utf-8") as fout:
			fout.write("hits~banner hash~banner data\n")
			for banner in self.bannerdic:
				bbanner = self.bannerdic[banner]
				bannerstring = self.replace_eols(bbanner["banner"])
				outstring = str(len(bbanner["probe-hitlist"])) + self.sep + str(banner) + self.sep + bannerstring + "\n"
				fout.write(outstring)
		# General scope report
		with codecs.open(self.scope_report_file, "w", encoding="utf-8") as fout:
			fout.write("Report on scope and by port: \n")
			active_probes = 0
			active_banners = 0
			tries = 0
			hits = 0
			for portnr in self.scope_report:
				tries += self.scope_report[portnr][0]
				hits += self.scope_report[portnr][1]
				active_probes += self.scope_report[portnr][2]
				active_banners += self.scope_report[portnr][3]			
			fout.write("Probes: overall / port-based:\t\t" + str(len(self.probedic)) + " / " + str(active_probes) + "\n")
			fout.write("Banners: overall / port-based:\t\t" + str(len(self.bannerdic)) + " / " + str(active_banners) + "\n")
			fout.write("Hits / tries:\t\t" + str(hits) + " / " + str(tries) + "\n")
			fout.write("hits~port~tries~probes~banners\n")
			#for key in sorted(dic): # sort the dictionary by key
			#	print ("%s: %s" % (key, dic[key]))
			
			for portnr in sorted(self.scope_report):
				x, y, z, a = self.scope_report[portnr] # By port: tries to hit, actual hits, number probes, number banners
				# !!! output order is different to store order
				outstring = str(y) + self.sep + str(portnr) + self.sep + str(x) + self.sep + str(z) + self.sep + str(a) +"\n"
				fout.write(outstring)
		
		# create the shodan cpe lists
		with codecs.open(self.shodan_cpes_present_file, "w", encoding="utf-8") as fout:
			fout.write("cpes-present~probe hash~banner hash\n")
			for x,y,z in self.shodan_cpes_present:
				outstring = str(x) + self.sep + str(y) + self.sep + str(z) + "\n"
				fout.write(outstring)
		with codecs.open(self.shodan_cpes_not_present_file, "w", encoding="utf-8") as fout:
			fout.write("cpes-not-present~probe hash~banner hash\n")
			for x,y,z in self.shodan_cpes_not_present:
				outstring = str(x) + self.sep + str(y) + self.sep + str(z) + "\n"
				fout.write(outstring)
		with codecs.open(self.probes_hit_banners_file, "w", encoding="utf-8") as fout:
			fout.write("probe hash~banner hash\n")
			for x,y in self.probes_hit_banners:
				outstring = str(x) + self.sep + str(y) + "\n"
				fout.write(outstring)
		with codecs.open(self.shodan_cpes_not_found_file, "w", encoding="utf-8") as fout:
			fout.write("port~shodan-cpe~banner hash\n")
			for x,y,z in self.shodan_cpes_not_found:
				outstring = str(x) + self.sep3 + str(y) + self.sep3 + str(z) + "\n"
				fout.write(outstring)
		print(">>> Other reports completed.")	
				
	def report_shodan_cpe_misses(self):
	# create a detailed report on the shodan-cpes that were not found:
	# load from csv (this function can become more independent)
		with codecs.open(self.shodan_cpes_not_found_file, "r", encoding="utf-8") as fin:
			with codecs.open(self.shodan_cpes_not_found_file_2, "w", encoding="utf-8") as fout:

				# skipping header line
				next(fin)
				for line in fin:
					#print(line)
					port, cpe, banner = line.split("~~~")
					banner = banner.rstrip()	# strip end of line	
					#cpes = cpes.replace("\'","\"")	# if the string contains single quotes ' , the string cannot be loaded as list, it must have double quotes "
					#print(cpes)
					#cpes = json.loads(cpes)			# encoding could be the problem. help link: http://code.opoki.com/loading-utf-8-json-file-in-python/
					#worthwhile = False								
					#for cpe in cpes:
					if not cpe.count(":") > 2:
						#worthwhile = True
						continue
					#if not worthwhile:
					#	continue
					
					fout.write(self.bannerdic[banner]["banner"])
					fout.write("\n" + "--"*20 + "------ below possible probes for above banner ----\n")
					fout.write(line)
					
					fout.write("--"*20 + "\n")
					# which probes could fit
					#for cpe in cpes:
					groupmatch = re.match(r'(.+?:.+?:.+?:.+?):', cpe)
					if groupmatch:
						regexx = groupmatch.group(1)
						for probe in self.probedic:
							pprobe = self.probedic[probe]
							for pcpe in pprobe["cpe"]:
								probematch = re.match(r"" + regexx + r"", pcpe)
								if probematch:
									fillin = str(pprobe["prefix"]) + "-" + str(pprobe["postfix"])
									fout.write("--"*20 + "\n")
									fout.write(str(pprobe["ports"]) + "\t" + probe + "\t" + fillin + "\t" + pcpe + "\t\t")
									fout.write(pprobe["regex"] + "\n")					
					fout.write("--"*20 + "\n")
					fout.write("--"*20 + "\n")					
		print(">>> Detailed report about MISSED Shodan-CPEs:", self.shodan_cpes_not_found_file_2)	
		
		#	cheat sheet for the result lists:
		#	self.shodan_cpes_present			# cpe present, probehash, bannerhash
		#	self.shodan_cpes_not_present		 # cpe not present, probehash, bannerhash
		#	self.probes_hit_banners		# probehash, bannerhash		# check double hits
		#	self.shodan_cpes_not_found 		 # cpe, bannerhash
		
		# This is stated script evolution process:
		# todo
		# how to reduce false negatives?
		# RE	- continue programming and reducing errors:
		#		OK	like backreferencing
		#		OK  report on testing scope: by port: probes, banners, hits: scope_report{}
		#		OK	take care of trailing slash in cpe comparisons
		#		OK	create function to report on not found shodan-cpes versus probes that contain that cpe, including back references.
		# ??	- put logical questions and examine like: is there a partial match and backreference if there is not a complete match?
		# RE	- check on backreference count mismatch reported by self.problems: created hit results, ok,
		# RE	- extend the database, optimise testing
		# RE	- check on shodan cpes
		#			=> Time freeze report: zz-reports-99-time-freeze-01		after attaining regex backreferences. 11 shodan-cpes not found.
		#			- OK Very important: Due to the json storage, the banners in the dictionary do not contain real \r and \n .
		#			and this could be the reasons for many misses. => replacing the \r and \n in the regex to \\r and \\n => almost,
		#			the problem is a \r\n at the end of regex. This does not makes sense. What is so important to test for an end of line?
		#			This must be a mistake. It prevents clearly sound matching for a superminimal chance to be correct in refusing.
		#			First I thought it was Windows putting thes line breaks, but they are in the middle of the lines in the downloaded
		#			nmap probe file. I will remove them:
		#			1) check hits after removing trailing \r\n , afterwards,
		#				=> only 8 shodan-cpes not found. the line breaks are actually: \\r\\n$
		#				! the \r\n is used in http for ending fields and messages. that could be the reason for http probes regex have this ending.
		#			2) if it worked, check also removing the \r . I know that raising the hits is not necessarily raising quality.
		#				=> not good. error "error: bad character range" in regex evaluation.
		#			=> Time freeze report: zz-reports-99-time-freeze-02		after removing probe regex final linebreak 
		#			Adding port 443 to the http-probes in portmapper file in source, also add 3306 for servicename "mysql"
		#			The portmapper info gets into the probes in 01-C-D, we need to rerun that and then 02 and then this here.
		#			=> all shodan-cpes found on 443, only 2 left: mysql and a http server on port 9000 that is not in port-based probing.
		#			=> Time freeze report: zz-reports-99-time-freeze-03
		#			we try to get the 3306 hit and manually check for a probe hit with the port 9000 http server:
		#			we use the shodan-cpes-not-found-2.txt report for this
		#				=> mysql uses an octal character encoding \0 and this is not in the shodan banner. 2 options
		#					?? - check for better encoding through python client and HTTP Request API
		#					?? - create new custom probes that potentially produce false positives, too.
		#				=> lighthttpd is on port 9000, so not in scope, but using the shodan-cpe report, we have a case
		#				that a probe would not have matched because it contains a \r in regex:
		#				probe: 847ebb43aa33a3e773bf880d16032a30		and banner:		7871a2cc0ab500f7b74c05c42505c98c
		#			=> most flexible solution for the future
		#			?? create functionality for custom probes
		#			OK create functionality for screening banners:
		#					-		\b(\w{4,})\b			flag g , matching all words and integer numbers with 4 characters or more.
		#					-		\d\.\d\S				flag g , matching all version numbers more detailed than x.y
		#
		# RE	- cleanup the code
		# RE	- check on double hits: self.probes_hit_banners, done for 7 hits,
		# OK	- consider to filter banners by regex for whole words
		# ??	- consider to write custom test probes to match certain banners
		# OK	- check on missing probes for empty portmapper port: => we do only use the probes with cpe!
		# OK	- check the port-based banner count in scope report: => we use unified banners that were found on more than one port.
		# OK	- logical error: the hits must be updated for best hits. many probes hitting a banner.
		# OK	- adding the hitlist reports of probes and banners
		# ??	- the shodan-cpes not present report contains cpes that were too weak to match shodan-cpes, perhaps an additional list?
		
		# RE	The trailing linebreak removal needs to be considered when building a hash and comparing against new probes!
		
		# OK	alpha stage:	make it run, solve errors
		# OK	beta stage:		look for special errors and improve the data and result quality so that it gets a basic usefulness
		
		# ??	backreference, middle \\r, compare with new data and document process, custom probes

	def screen_banners(self):
		# report on banner parts valuable for starting on creating custom probes
		pat_words = re.compile(r'\b(\w{4,})\b')
		pat_versionnumbers = re.compile(r'\d\.\d\S')
		words = {}
		versionnumbers = {}
		for banner in self.bannerdic:
			bbanner = self.bannerdic[banner]["banner"]
			result_words = re.findall(pat_words, bbanner)
			if result_words:				
				for word in result_words:
					if word in words:
						words[word] += 1
					else:
						words[word] = 1
			result_versionnumbers = re.findall(pat_versionnumbers, bbanner)
			if result_versionnumbers:
				for versionnumber in result_versionnumbers:
					if versionnumber in versionnumbers:
						versionnumbers[versionnumber] += 1
					else:
						versionnumbers[versionnumber] = 1
		
		
		# put the results to file:
		screened_words_file = "banner_screened_words.txt"
		screened_versions_file = "banner_screened_versionnumbers.txt"
		with codecs.open(self.reportfolder + screened_words_file, "w", encoding="utf-8") as fout:
			header = "Words found in banners, use for ideas for custom probes.\n"
			for word in sorted(words, key=words.get, reverse=True):
				fout.write(word + self.sep + str(words[word]) + "\n")
		with codecs.open(self.reportfolder + screened_versions_file, "w", encoding="utf-8") as fout:
			header = "Versionnumbers found in banners, use for ideas for custom probes.\n"
			for versionnumber in sorted(versionnumbers, key=versionnumbers.get, reverse=True):
				fout.write(versionnumber + self.sep + str(versionnumbers[versionnumber]) + "\n")
		print(">>> Banners screened:", self.reportfolder + screened_words_file, self.reportfolder + screened_versions_file)
		
	
	def report_probe_hitlist(self):
		probe_hitlist = []
		for probe in self.probedic:
			newentry = []
			pprobe = self.probedic[probe]
			if not pprobe["banner-hitlist"]:
				newentry.append(0)
			else:
				newentry.append(len(set(pprobe["banner-hitlist"])))
			newentry.append(str(pprobe["ports"]))
			newentry.append(probe)
			probe_hitlist.append(newentry)
		probe_hitlist = sorted(probe_hitlist, reverse=True)
		probe_hitlist_file = "probe-hitlist.txt"
		with codecs.open(self.reportfolder + probe_hitlist_file, "w", encoding="utf-8") as fout:
			header = "hits" + self.sep + "ports" + self.sep + "probe" + "\n"
			fout.write(header)
			for entry in probe_hitlist:				
				x, y, z = entry
				fout.write(str(x) + self.sep + str(y) + self.sep + z + "\n")
		print(">>> Probe ranking of hits:", self.reportfolder + probe_hitlist_file)
	
	def report_banner_hitlist(self):
		banner_hitlist = []
		for banner in self.bannerdic:
			newentry = []
			bbanner = self.bannerdic[banner]
			if not bbanner["probe-hitlist"]:
				newentry.append(0)
			else:
				newentry.append(len(set(bbanner["probe-hitlist"])))
			newentry.append(str(bbanner["ports"]))	
			newentry.append(banner)
			banner_hitlist.append(newentry)
		banner_hitlist = sorted(banner_hitlist, reverse=True)
		banner_hitlist_file = "banner-hitlist.txt"
		with codecs.open(self.reportfolder + banner_hitlist_file, "w", encoding="utf-8") as fout:
			header = "hits" + self.sep + "ports" + self.sep + "banner" + "\n"
			fout.write(header)
			for entry in banner_hitlist:
				x, y, z = entry
				fout.write(str(x) + self.sep + str(y) + self.sep + z + "\n")
		print(">>> Banner ranking of absorbed hits:", self.reportfolder + banner_hitlist_file)
	
	def report_banner_occurence(self):
		# overview about how many times an identical banner text has been found. We use consolidated banners, we do not have duplicate banner texts.
		banner_occurence_file = "banner_occurence.csv"
		with codecs.open(self.reportfolder + banner_occurence_file, "w", encoding="utf-8") as fout:
			header = "count" + self.sep + "ip-port-time" + self.sep + "banner" + "\n"
			fout.write(header)		
			for banner in self.bannerdic:
				if self.bannerdic[banner]["count"] > 1:
					bannerstring = self.bannerdic[banner]["banner"]
					bannerstring = self.replace_eols(bannerstring)
					outstring = str(self.bannerdic[banner]["count"]) + self.sep + str(self.bannerdic[banner]["ip-port-time"]) + self.sep + bannerstring + "\n"
					fout.write(outstring)
		print(">>> Banners occurences:", self.reportfolder + banner_occurence_file)
		
	
	def remove_regex_trailers(self):
		pat_linebreak = re.compile(r'\\r\\n$')
		countfound = 0
		for probe in self.probedic:			
			regex = self.probedic[probe]["regex"]
			if re.search(pat_linebreak, regex):
				newregex = re.sub(pat_linebreak, r'', regex)
				self.probedic[probe]["regex"] = newregex
				countfound += 1
		print("Found before Corrected:" , str(countfound))
		countfound = 0
		for probe in self.probedic:			
			regex = self.probedic[probe]["regex"]
			if re.search(pat_linebreak, regex):
				newregex = re.sub(pat_linebreak, r'', regex)
				self.probedic[probe]["regex"] = newregex
				countfound += 1
		print("Found before Corrected:" , str(countfound))
	
	def extract_ips(self):
		ips_extracted_file = "ips_extract.txt"
		with codecs.open(self.reportfolder + ips_extracted_file, "w", encoding="utf-8") as fout:
			ips = set()
			for banner in self.bannerdic:
				bbanner = self.bannerdic[banner]
				for ip in bbanner["ips"]:
					ips.add(ip)
			for ip in sorted(ips):
				fout.write(ip + "\n")
		print(">>> IPs from banners extracted:", self.reportfolder + ips_extracted_file)
	
	def extract_shodan_cpes(self):
		shodan_cpes_file = "shodan_cpes_extract.txt"
		with codecs.open(self.reportfolder + shodan_cpes_file, "w", encoding="utf-8") as fout:
			shodan_cpes = []
			count = 0
			cpe_count = 0
			for banner in self.bannerdic:
				bbanner = self.bannerdic[banner]
				if bbanner["shodan-cpes"]:
					newentry = [] # banner, shodan-cpes
					newentry.append(banner)
					newentry.append(bbanner["ports"])
					newentry.append(bbanner["shodan-cpes"])					
					shodan_cpes.append(newentry)
					count += 1
					cpe_count += len(bbanner["shodan-cpes"])			
			fout.write("Shodan-CPEs, Banner count and cpe count: " + str(count) + " / " + str(cpe_count) + "\n")
			for entry in shodan_cpes:
				x, y, z = entry
				fout.write(x + self.sep + str(y) + self.sep + str(z) + "\n")
		print(">>> Shodan-cpes extracted:", self.reportfolder + shodan_cpes_file)
	
	
	def single_probing(self):
		probehash = "82c04668c2784ab1469c6e35885e1261"
		bannerhash = "b5abb9538474955d2af5de49efb4ddaf"
		
		probe = self.probedic[probehash]
		banner = self.bannerdic[bannerhash]
		bcontent = banner["banner"]
		print(bcontent)
		print("--"*20)
		regex = probe["regex"]
		print(regex)
		print("--"*20)
		v1 = re.match(regex, bcontent, re.DOTALL)
		print("v1:",v1)
		v2 = re.match(r'^HTTP/1\.0 \d\d\d .*\r\nServer: lighttpd', bcontent, re.DOTALL)
		print("v2:",v2)
		v3 = re.match(r'^HTTP/1\.0 \d\d\d .*\nServer: lighttpd', bcontent, re.DOTALL)
		print("v3:",v3)
		
		postfix = probe["postfix"]
		print(postfix)
		regexflags = ""
		if postfix == "i":
			regexflags += "(?i)"		# case insensitive
		if postfix == "s":
			regexflags += "(?s)"		# dot matches new lines also
		if postfix == "m":
			regexflags += "(?m)"		# multiline
		if postfix == "x":
			regexflags += "(?x)"		# free spacing
		is_hit = False
		if regex[0] == '^':		# match from the beginning in python is re.match, otherwise re.search
			regex = regex[1:]
			xx_regexx = r"" + regexflags + regex + r""
			is_hit = re.match(xx_regexx, bcontent)
		else:
			xx_regexx = r"" + regexflags + regex + r""
			is_hit = re.search(xx_regexx, bcontent)
		print("regex:",xx_regexx)
		print("original:",is_hit)
		
		print(json.dumps(probe, indent=4))
		
	def single_probing_with_backreference(self, probehash, bannerhash):
			
		probe = self.probedic[probehash]
		banner = self.bannerdic[bannerhash]
		
		hit = {}	
		hit["count"] = 0
		hit["banner"] = banner["hash"]
		hit["ports"] = banner["ports"]
		hit["ips"] = banner["ips"]
		result= self.probing(banner, probe, hit)
		print(str(result))
						
try:
	
	
	P = Probing()					# 0			initializes banners and probes from json files
	
	### The below part is for manual single probing or probe / banner lookup.
	if len(sys.argv) > 1:
		if len(sys.argv) == 3:
			#P.single_probing()
			#manual testing function, using the backreference function of the main loop
			P.single_probing_with_backreference(sys.argv[1], sys.argv[2])
		
		probe = P.probedic.get(sys.argv[1], None)	# return None if key is not in dictionary						
		if probe is None:
			print(">>> Single input is not a probe hash, trying banner hash")
			banner = P.bannerdic.get(sys.argv[1], None)	# return None if key is not in dictionary
			if banner is None:
				print("!!> Invalid input. Provide a probe and / or banner hash, in this order.")
			else:
				print(json.dumps(banner,indent=4))
		else:
			print(json.dumps(probe,indent=4))
	### This is the passive probing
	else:
		P.screen_banners()				# 1			extract common words and version numbers from banners
		P.extract_ips()					# 1			extract ips from banners
		P.extract_shodan_cpes()			# 1			extract shodan-cpes from banners
		P.report_banner_occurence()		# 1			how many shodan banners are saved in a json banner?
		P.test()						# 2!		probes versus banners. !memory, time. only port-based at the moment, check
		
		P.report_shodan_cpe_misses() 	# 3-i-1		independent, 2 must have run once, after that it runs after init, takes input from file
		P.report_probe_hitlist()		# 3-i-1			report hits by probe
		P.report_banner_hitlist()		# 3-i-1			report hits on banner
			
		#P.inform_problems()					#	incomplete, optional		
	
except:
	print(traceback.format_exc())