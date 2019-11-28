# -*- coding: utf-8 -*-
import re
import json
import traceback
import os
import sys
#import hashlib
import codecs

# Priests arrange marriages of things that belong together: CVEs and IPs

class Priest():
	def __init__(self):
		self.meltingpotfolder = "./meltingpot/"
		self.probingfolder  = "./probing/"
		self.reportsfolder  = "./reports-99/"
		self.hostfolder = "./shodan-download/hosts/"
		
		self.cve_file_prefix = "nvdcve-2.0-"
		
		self.hits_file = "hits.json"
		self.nohits_file = "04-nohit.json"
		self.banners_file = "dic-banners.json"
		self.cpe3_matcher_file = "cpe3-matcher.json"
		
		self.reporter_ip_json_file = "cpe4-cves-by-ip.json"
		self.shodan_hosts_file = "shodan-hosts.json"
		self.marriages_file = "marriages.json"
		
		self.reporter_ip_file = "final-cpe4-cves-by-ip.csv"		
		self.reporter_cpe4_file = "final-cpe4-cves.csv"
		self.reporter_cpe3_file = "final-cpe3-cves.csv"
		self.reporter_cve_cpe3_file = "final-cves-of-cpe3.csv"
		self.matching_report_file = "final-cpe3-cves-matching-report.txt"
		
		self.cve_files = set()
		self.marriage = {}		
		
		self.hits = {}
		self.nohits = []
		self.bannerdic = {}
		self.cpe3_matcher = {}
		self.cvedics = {}
		self.shodanhostsdic = {}
		
		self.sep = "~"
		
		self.identify_cve_files()
		self.load_all()		
		print(">>> ceremony prepared.")	
			
	def identify_cve_files(self):
		folder = self.meltingpotfolder
		for the_file in os.listdir(folder):			
			file_path = os.path.join(folder, the_file)
			if os.path.isfile(file_path):				
				if the_file[-5:] == ".json":
					if the_file[:len(self.cve_file_prefix)] == self.cve_file_prefix:
						self.cve_files.add(the_file)
						print(">>> Found cve source file:", self.meltingpotfolder + the_file)					
	
	def load_all(self):	
		with codecs.open(self.probingfolder + self.banners_file, "r", encoding="utf-8") as fin:
			self.bannerdic = json.load(fin)
		with codecs.open(self.meltingpotfolder + self.nohits_file, "r", encoding="utf-8") as fin:
			self.nohits = json.load(fin)		
		with codecs.open(self.meltingpotfolder + self.cpe3_matcher_file, "r", encoding="utf-8") as fin:
			self.cpe3_matcher = json.load(fin)		
		with codecs.open(self.meltingpotfolder + self.hits_file, "r", encoding="utf-8") as fin:
			lines = fin.readlines()
			for line in lines:
				hit = json.loads(line)
				self.hits[hit["banner"]] = hit
		for inputfile in self.cve_files:
			year = re.match(r"" + self.cve_file_prefix + r"(\d\d\d\d)", inputfile)
			if not year:
				print("!!> Problem matching file name parsing, please check:", self.meltingpotfolder + inputfile)
				raise "!!> Problem matching file name parsing, please check:" + self.meltingpotfolder + inputfile
			with codecs.open(self.meltingpotfolder + inputfile, "r", encoding="utf-8") as fin:
				mydic = json.load(fin)				
				self.cvedics[year.group(1)] = mydic	
	
	def load_marriage(self):
		# load marriage data from json
		with codecs.open(self.meltingpotfolder + self.marriages_file, "r", encoding="utf-8") as fin:
			self.marriage = json.load(fin)
			
	def proceedings(self):
		# run through hits and marry
		# we will produce level 4 (version) and better matches
		# the level 3 matches will just be count
		print(">>> Starting matching...")	
		marriage = {}		
		level3_matches = {}
		level3_misses = set()
		level4plus_matches = {}
		level2 = set()
		
		def marry(hit):			
			nonlocal level3_matches
			nonlocal level3_misses
			pat_3 = re.compile(r"(cpe:/.:.+?:.+?)(:|$)")
			newmarriage = {}
			newmarriage["cpe"] = hh["cpe"]				
			newmarriage["matchscore"] = 0		# level 3 hit is 1, better hit is 3
			newmarriage["cves"] = {}
			newmarriage["cpe3-matched"] = []
			for cpe in hh["cpe"]:
				level = cpe.count(":")
				if  level < 3:
					level2.add(cpe)
					continue
					# we do nothing with them, just storing
				else:
					match = re.match(pat_3, cpe)
					cpe3 = match.group(1)					
					if cpe3 in self.cpe3_matcher:						
						newmarriage["matchscore"] += 1
						if not cpe3 in newmarriage["cpe3-matched"]:
							newmarriage["cpe3-matched"].append(cpe3)
						if cpe3 in level3_matches:
							level3_matches[cpe3] += 1
						else:
							level3_matches[cpe3] = 1						
						if level > 3:
							# check for better match							
							for cve in self.cpe3_matcher[cpe3]:
								cpe_plus_list = self.cpe3_matcher[cpe3][cve]
								for cpe_plus in cpe_plus_list:									
									if cpe_plus[:len(cpe)] == cpe:										
										newmarriage["matchscore"] += 3										
										if cpe in level4plus_matches:
											level4plus_matches[cpe] += 1
										else:
											level4plus_matches[cpe] = 1										
										# add cve based on version or better:
										if not cpe in newmarriage["cves"]:
											newmarriage["cves"][cpe] = []
										newmarriage["cves"][cpe].append(cve)
										break
					else:
						level3_misses.add(cpe3)
			return newmarriage			
		
		for hit in self.hits:						# process the nmap hits	
			hh = self.hits[hit]
			marriage[hit] = marry(hh)				# action
		for banner in self.nohits:					# process the shodan-cpes without hit			
			marriage[banner] =  marry(banner)		# action
		
		with codecs.open(self.meltingpotfolder + self.marriages_file, "w", encoding="utf-8") as fout:
			json.dump(marriage, fout)
		print(">>> Matching complete and saved to:", self.meltingpotfolder + self.marriages_file)	
		
		with codecs.open(self.reportsfolder + self.matching_report_file, "w", encoding="utf-8") as fout:		
			fout.write("=="*30 + "\n")
			fout.write("# " + str(len(level2)) + " of level-2 or less cpes were ignored:" + "\n")
			for l2 in level2:
				fout.write(l2 + "\n")
			fout.write("=="*30 + "\n")
			fout.write("# " + str(len(marriage)) + " different banners with at least level-3 cpes (product) were processed" + "\n")
			fout.write("=="*30 + "\n")
			fout.write("# " + str(len(level4plus_matches)) + " different level-4 cpes (version) with at least one length version number were matched to CVEs, occurence ranking" + "\n")
			for count in sorted(level4plus_matches, key=level4plus_matches.get, reverse=True):
				fout.write(str(level4plus_matches[count]) + "\t" + str(count) + "\n")
			fout.write("=="*30 + "\n")
			fout.write("# " + str(len(level3_matches)) + " level-3 cpes matched to CVEs, occurence ranking" + "\n")
			for count in sorted(level3_matches, key=level3_matches.get, reverse=True):
				fout.write(str(level3_matches[count]) + "\t" + count + "\n")
			fout.write("=="*30 + "\n")
			fout.write("# " + str(len(level3_misses)) + " level-3 cpes that are unknown to the CVEs of the involved years" + "\n")
			for x in level3_misses:
				fout.write(x + "\n")
			fout.write("=="*30 + "\n")
		

	######################################################################################
	#	json dictionary cheat sheets:		NVD - World
	#	## annual cves					## cpe dictionary		## vendor statements		## cpe matcher
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
	#					Probe-Hits-World						
	#	## Probe-Hits					## No-Hits				## Marriages
	#	##key: banner					## 						## key: banner / hit hash	
	#	hit["count"]					[] of banner			mm["cves"][cpe4+] [] of cves		
	#	hit["banner"]											mm["matchscore"]		+1 for cpe3-hit, +3 for cpe4+ hit
	#	hit["ports"]											mm["cpe"]				usual cpes got from banner
	#	hit["ips"]												mm["cpe3-matched"] [] of matched cpe3
	#	hit["probe"]											mm[""]	
	#	hit["version"]												
	#	hit["i"]			
	#	hit["product"]						
	#	hit["cpe"]						
	#	hit["os"]				
	#	
	######################################################################################
	
	def create_shodanhostdic(self):
		for file in os.listdir(self.hostfolder):
				current_file = os.path.join(self.hostfolder, file)
				with codecs.open(current_file, 'r', encoding='utf8') as infile:
					data = infile.readlines()
					for line in data: 
						current_host = json.loads(line) # host info consists of main and data subinfo in which the ports are
						ip = current_host["ip_str"]
						self.shodanhostsdic[ip] = current_host
		with codecs.open(self.meltingpotfolder + self.shodan_hosts_file, "w", encoding="utf-8") as fout:
			json.dump(self.shodanhostsdic, fout)
		print(">>> Shodan hosts dictionary created:", self.meltingpotfolder + self.shodan_hosts_file)	
		
	def load_shodanhostdic(self):
		with codecs.open(self.meltingpotfolder + self.shodan_hosts_file, "r", encoding="utf-8") as fin:
			self.shodanhostsdic = json.load(fin)
		print(">>> Shodan hosts dictionary loaded")
	
	def lookup_shodan_vulns(self, ip):
		host = self.shodanhostsdic[ip]
		vulns = []
		if "vulns" in host:
			for vuln in host['vulns']:
				vulns.append(vuln)
		return vulns
		
	def overview_cve_cpe3(self):
		cves = {}
		for cpe3 in self.cpe3_matcher:			
			for cve in self.cpe3_matcher[cpe3]:
				if not cve in cves:
					cves[cve] = set()
					cves[cve].add(cpe3)
				else:
					cves[cve].add(cpe3)
		#cves = sorted(cves, reverse=True)
		# creating report
		with codecs.open(self.reportsfolder + self.reporter_cve_cpe3_file, "w", encoding="utf-8") as fout:
			header = ("c", "CVE", "CVSS", "cpe", "CVE description")
			headerstring = ""
			for h in header:
				headerstring += h + self.sep
			headerstring += "\n"			
			fout.write(headerstring)				
			outstring = ""
			for cve in reversed(sorted(cves.keys())):
				cve_lookup = self.get_cve_info(cve) # cve lookup
				outstring = str(len(cves[cve])) + self.sep + cve + self.sep + cve_lookup["cvss"] + self.sep				
				first = True	
				for cpe3 in cves[cve]:					
					if first:
						outstring += cpe3 + self.sep + cve_lookup["text"] + "\n"
						first = False
					else:
						outstring += 3* self.sep + cpe3 + "\n"					
				fout.write(outstring)							
		print(">>> CVEs of cpe3 report created:", self.reportsfolder + self.reporter_cve_cpe3_file)	
	
	def report_cpe3(self):
		self.load_marriage()
		print(">>> Creating cpe3 report.")
		cpe3s = {}
		cpe3s_cves = {}
		for m in self.marriage:
			mm = self.marriage[m]
			for cpe3 in mm["cpe3-matched"]:				
				if cpe3 in cpe3s:
					cpe3s[cpe3] += 1					
				else:
					cpe3s[cpe3] = 1
					cpe3s_cves[cpe3] = []
					for cve in self.cpe3_matcher[cpe3]:
						cpe3s_cves[cpe3].append(cve)					
		print(">>> cpe3 data collected, exporting...")					
				
		# cpe3s collected, now the report
		with codecs.open(self.reportsfolder + self.reporter_cpe3_file, "w", encoding="utf-8") as fout:
			header = ("c", "cpe3", "CVEs", "CVSS")
			headerstring = ""
			for h in header:
				headerstring += h + self.sep
			headerstring += "\n"			
			fout.write(headerstring)				
			outstring = ""
			for cpe3 in cpe3s:
				outstring = str(cpe3s[cpe3]) + self.sep + cpe3 + self.sep
				cpe3_old = ""				
				for cve in cpe3s_cves[cpe3]:
					cve_lookup = self.get_cve_info(cve) # cve lookup
					if cpe3_old == cpe3:
						outstring += "\n" + 2 * self.sep + cve + self.sep + cve_lookup["cvss"]
					else:
						outstring += cve + self.sep + cve_lookup["cvss"]
					cpe3_old = cpe3
				fout.write(outstring + "\n")						
		print(">>> cpe3 report created:", self.reportsfolder + self.reporter_cpe3_file)	
	
	def report_cpe4(self):
		self.load_marriage()
		print(">>> Creating cpe4 report.")
		cpe4s = {}
		cpe4s_cves = {}
		for m in self.marriage:
			mm = self.marriage[m]
			for cpe4 in mm["cves"]:				
				if cpe4 in cpe4s:
					cpe4s[cpe4] += 1					
				else:
					cpe4s[cpe4] = 1
					cpe4s_cves[cpe4] = mm["cves"][cpe4]
		print(">>> cpe4 data collected, exporting...")					
					
		# cpe4s collected, now the report
		with codecs.open(self.reportsfolder + self.reporter_cpe4_file, "w", encoding="utf-8") as fout:
			header = ("c", "cpe4+", "CVEs", "CVSS", "CVE description")
			headerstring = ""
			for h in header:
				headerstring += h + self.sep
			headerstring += "\n"			
			fout.write(headerstring)				
			outstring = ""
			for cpe4 in cpe4s:
				outstring = str(cpe4s[cpe4]) + self.sep + cpe4 + self.sep
				cpe4_old = ""				
				for cve in cpe4s_cves[cpe4]:
					cve_lookup = self.get_cve_info(cve) # cve lookup
					if cpe4_old == cpe4:
						outstring += "\n" + 2 * self.sep + cve + self.sep + cve_lookup["cvss"] + self.sep + cve_lookup["text"]
					else:
						outstring += cve + self.sep + cve_lookup["cvss"] + self.sep + cve_lookup["text"]
					cpe4_old = cpe4
				fout.write(outstring + "\n")			
		print(">>> cpe4 report created:", self.reportsfolder + self.reporter_cpe4_file)	
	
	def report_by_ip(self):
		
		def ip_port_only(list_of_ip_port_time_tuples):
			ip_port_tuples = set()
			for tuple in list_of_ip_port_time_tuples:
				ip, port, timestamp = tuple
				ip_port_tuples.add((ip, port))
			return ip_port_tuples		
		
		self.load_marriage()
		
		# collect ips from all banners
		cve_ips = set()
		non_cve_ips = set()
		for banner in self.bannerdic:
			bbanner = self.bannerdic[banner]
			if banner in self.marriage:
				for ip in bbanner["ips"]:
					cve_ips.add(ip)
			else:
				for ip in bbanner["ips"]:
					non_cve_ips.add(ip)
		# => ips in two sets, but ip could be in both, in which case it should not be in non_cve_ips:
		# s.difference(t) 	s - t 	new set with elements in s but not in t
		non_cve_ips = non_cve_ips.difference(cve_ips)
		
		# produce an ip-based list on cves
		# prepare reporter_ip:
		print(">>> Creating data structure for IP-report.")
		reporter_ip = {}
		for ip in cve_ips:			
			reporter_ip[ip] = {}
			r = reporter_ip[ip]
			r["matchscore-ip"] = 0
			r["ports"] = {}
		# loop the cve-cpe-marriages and fill up reporter		
		for m in self.marriage:
			mm = self.marriage[m]		
			bbanner = self.bannerdic[m]
			ip_port_tuples = ip_port_only(bbanner["ip-port-time"])
			for tuple in ip_port_tuples:
				ip, port = tuple			
				reporter = reporter_ip[ip]
				portdic = reporter.get(port, None)	# return None if key is not in dictionary						
				if portdic is None:					
					reporter["ports"][port] = {}
					portdic = reporter["ports"][port]
					portdic["cpe3"] = []
					portdic["cpe4"] = {}
				for cpe3 in mm["cpe3-matched"]:
					portdic["cpe3"].append(cpe3)
				for cpe4 in mm["cves"]:
					#portdic["cpe4"][cpe4] = []
					portdic["cpe4"][cpe4] = mm["cves"][cpe4].copy()					
				portdic["matchscore"] = mm["matchscore"]
		# do not forget to finalize the ip matchcount
		for ip in reporter_ip:
			matchscore = 0
			iip = reporter_ip[ip]
			for port in iip["ports"]:
				pport = iip["ports"][port]
				matchscore += pport["matchscore"]
			iip["matchscore-ip"] = matchscore		
		
		with codecs.open(self.meltingpotfolder + self.reporter_ip_json_file, "w", encoding="utf-8") as fout:
			json.dump(reporter_ip, fout)
		print(">>> Data structure created and dumped to :", self.meltingpotfolder + self.reporter_ip_json_file)		
		
		# we got the data, now let us put it into a csv file
		with codecs.open(self.reportsfolder + self.reporter_ip_file, "w", encoding="utf-8") as fout:
			header = ("s", "ip", "s", "port", "cpe4+", "CVEs", "CVSS", "Shodan", "Shodan-all")
			headerstring = ""
			for h in header:
				headerstring += h + self.sep
			headerstring += "\n"			
			fout.write(headerstring)				
			outstring = ""
			for ip in reporter_ip:									
				iip = reporter_ip[ip]				
				## load shodan vulnerabilities				
				shodan_vulns = self.lookup_shodan_vulns(ip)
				shodan_vulns = set(shodan_vulns)
				shodan_vulns_found = set()
				# this is the cpe4 report, only report these ips
				cpe4_present = False
				for port in iip["ports"]:
					pport = iip["ports"][port]					
					if pport["cpe4"]:
						cpe4_present = True
				if not cpe4_present:					
					continue
				outstring = str(iip["matchscore-ip"]) + self.sep + ip + self.sep
				ip_old = ""
				for port in iip["ports"]:
					pport = iip["ports"][port]
					if ip_old == ip:
						outstring += "\n" + 2 * self.sep + str(pport["matchscore"])+ self.sep + str(port) + self.sep
					else:
						outstring += str(pport["matchscore"])+ self.sep + str(port) + self.sep
					ip_old = ip
					port_old = ""					
					for cpe4 in pport["cpe4"]:
						ccpe4 = pport["cpe4"][cpe4]
						if port_old == port:
							outstring += "\n" + 4 * self.sep + cpe4 + self.sep
						else:
							outstring += cpe4 + self.sep
						port_old = port
						cpe4_old = ""							
						for cve in ccpe4:
							shodanstring = ""
							for scve in shodan_vulns:								
								if cve == scve:
									shodanstring = scve
									shodan_vulns_found.add(scve)
								elif cve == scve[1:]:
									shodanstring = scve
									shodan_vulns_found.add(scve)
							cve_lookup = self.get_cve_info(cve) # cve lookup
							if cpe4_old == cpe4:
								outstring += "\n" + 5 * self.sep + cve + self.sep + cve_lookup["cvss"] + self.sep + shodanstring
							else:
								outstring += cve + self.sep + cve_lookup["cvss"] + self.sep + shodanstring + self.sep + str(shodan_vulns)
							cpe4_old = cpe4
				fout.write(outstring + "\n")
		print(">>> Report CVEs by IP complete:", self.reportsfolder + self.reporter_ip_file)
			
		# OK -- Report: CVEs by IP:		matchcount		ip		matchcount		port	cpe4+		CVEs	CVSS
		# OK -- Report: CVEs by cpe4+:	count			cpe4+	CVEs	CVSS		CVE description
		# OK -- Report: CVEs by cpe3:	count			cpe3	CVEs
		# OK -- Report: CVEs for cpe3:	count			CVE		cpe3	CVSS	CVE description
		# OK -- Report:	compare against cves found by shodan, as an add-on to IP-List		
	
	def print_cpe3_matcher(self):
		print(json.dumps(self.cpe3_matcher, indent=4))	
	
	# manual check on cve in cve dictionary
	def print_cve(self, cve):
		cyear = cve[4:8]
		cvedic = self.cvedics[cyear]
		cc = cvedic[cve]
		print(json.dumps(cc, indent=4))
	
	def get_cve_info(self, cve):
		cyear = cve[4:8]
		cve = self.cvedics[cyear][cve]
		return cve	
	
try:
	
	# runtime action
	Priest = Priest()						#1		loads all json files into memory		
	Priest.proceedings()					#2		marries cpe3 and better to cves, produces json marriage file and matching report
	Priest.create_shodanhostdic()			#2A		takes the single host files from download and creates a host dictionary.
	Priest.load_shodanhostdic()				#3iA	
	Priest.report_by_ip()					#3iA	creates a cpe4 report based on ips, saved ip-based data structure to json file
	Priest.report_cpe4()					#3i		creates report to cpe4s with descriptions
	Priest.report_cpe3()					#3i		creates report to cves belonging to cpe3s
	Priest.overview_cve_cpe3()				#2		report of cves with their cpe3s.
	
	#Priest.print_cpe3_matcher()				#2		just see cve distribution in json data

except:
	print(traceback.format_exc())