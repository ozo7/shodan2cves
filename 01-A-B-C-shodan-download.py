# -*- coding: utf-8 -*-
import re
import shodan
import json
import traceback
import sys
import itertools
import os
import hashlib
import time
import shutil
import codecs

class Shodan_Downloader():
# vulnerability information is only available on the host object which can only be requested by providing a single ip.
# therefore, if doing a CIDR check, there is first a shodan search which reveals valid ips in that ip range.
# Also, a usual search will find banners and save to file, but also another file containing the ips found in the banners.
# Either way, the retrieved ips are stored and can be loaded in the queue for hosts download.
# thereafter, the single ips are requested by the host method and checked for vulnerabilities.

# preconditions:	input is a ip or CIDR in each line of inputfile, but CIDR at /24 only. A usual search input is also possible.
# postconditions:	usual search: a banner dictionary file and an ip list file. hosts: IP-based json banner data in destfolder/hosts/

	def __init__(self, shodan_api, destfolder, inputfile):
		self.shodan_api = shodan_api
		self.destfolder = destfolder
		self.reportfolder = "./reports-99/"
		self.probingfolder = "./probing/"
		self.inputfile = inputfile
		self.subdirs = ["hosts",]
		self.sep = "~"
		
		# search vars
		self.ips_processed_banners = set()	# stores all ips processed from banner download
		#self.ips_processed_hosts = set()	# stores all ips processed from host download
		self.ips_without_banner = set()		# stores all ips without banner data
		self.ipsv6 = set()					# stores all ipsv6
		self.last_search = ""
		self.banners_file = "bannersearch.json"
		self.ips_from_downloaded_banners_file = "ips-from-downloaded-banners.json"
		
		# hosts vars
		self.ips2process = []			# the current process queue for hosts
		self.ips_processed = []
		self.ips_failed = []
		self.ips_notfound = []
		
		self.pat_comment = re.compile(r'#')
		
		# report vars
		self.mode = ""	
		self.checkdestfolder()
	
	def clear_all_queues(self):
		self.ips2process = []
		self.ips_processed = []
		self.ips_failed = []
		self.ips_notfound = []
		
	def checkdestfolder(self):
		for subdir in self.subdirs:
			directory = destfolder + subdir
			if not os.path.exists(directory):
				os.makedirs(directory)

	def prepare_processed(self):
		self.ips2process = self.ips_processed
		self.ips_processed = []
		self.ips_failed = []
		self.ips_notfound = []

	def report(self):
		print("Report for hosts:")		
		header = ["ips2process", "ips_processed", "ips_failed", "ips_notfound"]
		print ('{:18}{:18}{:18}{:18}'.format(*header))
		# we need to fillup the empties to zip several lists
		ips2process = self.ips2process
		ips_processed = self.ips_processed
		ips_failed = self.ips_failed
		ips_notfound = self.ips_notfound
		maxx = max(len(self.ips2process), len(self.ips_processed), len(self.ips_failed), len(self.ips_notfound))
		ips2process = ips2process + ['-']*(maxx - len(ips2process))
		ips_processed = ips_processed + ['-']*(maxx - len(ips_processed))
		ips_failed = ips_failed + ['-']*(maxx - len(ips_failed))
		ips_notfound = ips_notfound + ['-']*(maxx - len(ips_notfound))
		output = zip(ips2process, ips_processed, ips_failed, ips_notfound)
		for row in output:
			print ('{:18}{:18}{:18}{:18}'.format(*row))

	def shodan_info(self):
		print (json.dumps(self.shodan_api.info(), indent=4))

	def load_ips_from_file(self, inputfile):
		self.clear_all_queues()
		self.ips_failed = []
		fin = open(inputfile, "r")
		data = fin.readlines()
		for ip in data:
			if self.pat_comment.match(ip):
				continue
			self.ips2process.append(ip.rstrip())
		self.ips2process = sorted(set(self.ips2process))
		fin.close()
		print(">>> IPs from search loaded: ", str(len(self.ips2process)))
		
	def cleanupfiles(self):
		for subdir in self.subdirs:
			folder = self.destfolder + subdir
			for the_file in os.listdir(folder):
				file_path = os.path.join(folder, the_file)
				try:
					if os.path.isfile(file_path):
						os.unlink(file_path)
					#elif os.path.isdir(file_path): shutil.rmtree(file_path) # traverses also subdirectories
				except Exception as e:
					print (e)

	def search(self, search):
		print(">>> Search requested:", search)			
		self.ips_processed_banners = set()	# stores all ips processed from banner download
		# provide for paging, each page contains up to 100 results
		page = 0
		more_results = True
		downloaded = 0
		bannerdic = {}	# dictionary to keep all the results
		counter_banners_empty = 0
		counter_banners_valid = 0
		counter_banners_multiple = 0
		counter_banners_ipv6 = 0
		maxpage = 1
		results_per_page = 100
		self.last_search = search
			
		def process_page():
			nonlocal counter_banners_empty	# only python 3: to reference a variable in the outer function, but not further, otherwise we have 'global'	
			nonlocal counter_banners_valid
			nonlocal counter_banners_multiple
			nonlocal counter_banners_ipv6
			nonlocal bannerdic
			for result in searchresults['matches']:
				ip = result["ip_str"]
				if ":" in ip: #This is an IPv6
					counter_banners_ipv6 += 1						
					self.ipsv6.add(ip)
					continue
				if result["data"] is None:
					counter_banners_empty += 1						
					self.ips_without_banner.add(ip)
					continue
				else:
					hash = hashlib.md5(result["data"].encode('utf8')).hexdigest()
					
					bbanner = bannerdic.get(hash, None)	# return None if key is not in dictionary						
					if bbanner:						
						port = result["port"]
						# there are doubles because of timestamp, we just take a count if ip and port were different.
						if not result["ip_str"] in bbanner["ips"]:
							if not port in bbanner["ports"]:
								bbanner["ports"].append(port)								
								bbanner["ips"].append(result["ip_str"])
								ip_port_time = (result["ip_str"], result["port"], result["timestamp"])
								bbanner["ip-port-time"].append(ip_port_time)					
								bbanner["count"] += 1
						if "cpe" in result:
							for cpe in result["cpe"]:
								# remove trailing slash /$ for better comparison
								if cpe[-1:] == "/":
									cpe = cpe[:-1]
						counter_banners_multiple += 1
						if ip in self.ips_without_banner:
							self.ips_without_banner.remove(ip)
						self.ips_processed_banners.add(ip)								
					else:
						newbanner = {}						
						newbanner["hash"] = hash
						newbanner["ports"] = []
						newbanner["ports"].append(result["port"])
						newbanner["ips"] = []
						newbanner["ips"].append(result["ip_str"])
						newbanner["ip-port-time"] = []
						ip_port_time = []
						ip_port_time = (result["ip_str"], result["port"], result["timestamp"])						
						newbanner["ip-port-time"].append(ip_port_time)
						newbanner["probe-hitlist"] = []
						newbanner["banner"] = result["data"]
						newbanner["banner-length"] = len(result["data"])
						newbanner["count"] = 1
						newbanner["shodan-cpes"] = []
						if "cpe" in result:
							for cpe in result["cpe"]:
								# remove trailing slash /$ for better comparison
								if cpe[-1:] == "/":
									cpe = cpe[:-1]
								# remove trailing /a for better comparison
								if cpe[-2:] == "/a":
									cpe = cpe[:-2]
								newbanner["shodan-cpes"].append(cpe)
						newbanner["cpes"] = []
						newbanner["remark"] = ""
						newbanner["flags"] = []							
						
						bannerdic[hash] = newbanner
						counter_banners_valid += 1
						if ip in self.ips_without_banner:
							self.ips_without_banner.remove(ip)
						self.ips_processed_banners.add(ip)
	
		try:				
			
			while more_results:
				page += 1
				fillin = ""
				pagestring = ("# page: " + str(page))
				for attempt in range(3):
					try:
						searchresults = self.shodan_api.search(search, page=page, limit=None, offset=None, facets=None, minify=True)
					except shodan.APIError as e:
						fillin = "." + "!"*attempt
						sys.stdout.write('\r')				
						sys.stdout.write(fillin + "\r")
						sys.stdout.flush()						
						time.sleep(4)
					else:
						break
				else:
					# we failed all the attempts - deal with the consequences.
					print("!!! Problem getting download. Try 'again' to retry it.\n")
					# store banners dictionary to json					
					with codecs.open('partial_bannersearch.json', 'w', encoding="utf-8") as file:
						json.dump(bannerdic, file)		
					return
					print("!!! Partial download stored.\n")
					
				sys.stdout.write('\r')				
				sys.stdout.write(">>> " + pagestring + " of " + str(maxpage) + ",  downloaded: " + str(downloaded) + "\r")
				sys.stdout.flush()
				# just for the first loop, ugly but sufficient:
				if page == 1:
					total = int(searchresults['total'])
					if  total == 0:
						print(">>> No results for search:", search)
						return
					maxpage = (total // results_per_page) + 1				
				process_page()
				downloaded += len(searchresults["matches"])
				if page == maxpage:
					more_results = False
		
			# store banners dictionary to json					
			with codecs.open(self.destfolder + self.banners_file, 'w', encoding="utf-8") as file:
				json.dump(bannerdic, file)
			print(">>> Banner dictionary stored into file.\n")
			# store valid ips found to json
			ip_list = []
			for ip in self.ips_processed_banners:
				ip_list.append(ip)
			with codecs.open(self.destfolder + self.ips_from_downloaded_banners_file, 'w', encoding="utf-8") as file:
				json.dump(ip_list, file)
			print(">>> IPs in banners stored into file.")
			# report
			print(">>> Search downloaded, results total:", str(downloaded))
			print(">>> Banner results: Valid, Multiple, NoData, IPv6: ", str(counter_banners_valid) + " / " + str(counter_banners_multiple) + " / " + str(counter_banners_empty) + " / " + str(counter_banners_ipv6) + "\n")
			self.ips_processed_banners = set()
			self.ips_without_banner = set()
			self.ipsv6 = set()
		except Exception as e:
			print("\n")
			print("--"*20)
			print(traceback.format_exc())
			print("--"*20)			
		
	def get_ip_host(self, ip_str):
		try:
			# get the shodan-object of host, with vulnerability information that is only there
			host = None
			host = api.host(ip_str, history=False)
			if not host:
				self.ips_notfound.append(ip_str)
				return
			else:
				ipfile = destfolder + 'hosts/' + ip_str + '.json'
				with codecs.open(ipfile, 'a', encoding="utf-8") as hostfile:
					json.dump(host, hostfile)
					hostfile.write("\n")
				self.ips_processed.append(ip_str)
				
		except Exception as e:
			print('failed IP: ',ip_str, 'Error: ',e)
			self.ips_failed.append(ip_str)
	
	def hosts(self):
		# it is cluttered because of the progress bar.
		max = len(self.ips2process)
		print ('IPs to process:\t',max)
		c = 1
		sys.stdout.write('\r')
		for ip in self.ips2process:
			self.get_ip_host(ip)			
			# a progress bar
			sys.stdout.write('\r')
			part = c * 50 // max # max -1 if index is 0 and not 1
			sys.stdout.write("[%-50s] %d%%" % ('='*part, c*100//max))
			sys.stdout.flush()
			c += 1

	def user_interaction(self, choice):
		print("Last action: ", choice)
		nextAction = \
		"Please chose next action:\n\
		! Do a download in one session, otherwise overwrites!\n\
		! Always this order: search-ipsfromsearch-hosts-again\n\
		! or only loadfile-hosts-again-report\n\
		>>> search: usual search like on website, e.g. filters\n\
		>>> ipsfromsearch: after search, load collected ips\n\
		>>> loadfile: load host ips from file\n\
		>>> hosts: download all by ip queue, includes vulns\n\
		>>> again: try job again. This works with search and hosts\n\
		>>> report: print report and ask again\n\
		>> banneroccurence: create a csv report on occurence\n\
		> removefailed: so that they are not in redo again\n\
		> removenotfound: so that they are not in redo again\n\
		> clear: clear all ip queues\n\
		> delete: delete all downloads\n\
		> abort: abort\n"
		print (nextAction),
		choice = input().lower()
		if choice == 'search':
			self.mode = choice
			prompt = "Please enter the search string: \nUse hostname, port, country, net, OR, !, AND\n"
			print (prompt),
			search = input().lower()
			self.search(search)
			self.copy_banners2probing()			
			self.user_interaction(choice)
		elif choice == 'ipsfromsearch':			
			self.load_ips_from_downloaded_banners()
			self.user_interaction(choice)			
		elif choice == 'loadfile':			
			self.load_ips_from_file(inputfile)
			self.user_interaction(choice)
		elif choice == 'hosts':
			self.mode = choice
			self.cleanupfiles()
			self.hosts()
			self.report()			
			self.user_interaction(choice)
		elif choice == 'again':
			if self.mode == 'hosts':
				self.ips2process = self.ips_failed + self.ips_notfound 
				self.ips_processed = []
				self.ips_failed = []
				self.ips_notfound = []
				self.hosts()
				self.report()				
				self.user_interaction(choice)
			if self.mode == 'search':
				self.search(self.last_search)
				self.copy_banners2probing()					
				self.user_interaction(choice)
		elif choice == 'report': 
			self.report()
			self.user_interaction(choice)
		elif choice == 'banneroccurence': 
			self.report_banner_occurence()
			self.user_interaction(choice)			
		elif choice == 'removefailed':
			self.ips_failed = []
			self.user_interaction(choice)
		elif choice == 'removenotfound':
			self.ips_notfound = []
			self.user_interaction(choice)
		elif choice == 'clear':
			self.clear_all_queues()
			self.user_interaction(choice)				
		elif choice == 'delete':
			self.cleanupfiles()
			self.user_interaction(choice)
		elif choice == 'abort':
			print('Aborted.')
		else:
			print('Not a valid answer: ', str(choice),' Try again.')
			self.user_interaction("Not valid")
	
	def load_ips_from_downloaded_banners(self):
		self.clear_all_queues()		
		with codecs.open(self.destfolder + self.ips_from_downloaded_banners_file, 'r', encoding="utf-8") as fin:
			ip_list = json.load(fin)
		self.ips2process = sorted(set(ip_list))
		self.ips_processed = []
		self.ips_failed = []
		self.ips_notfound = []
		print(">>> IPs from search loaded: ", str(len(self.ips2process)))
	
	def replace_eols(self, string):
		string = string.replace('\r','---r---')
		string = string.replace('\n','---n---')
		return string
	
	def report_banner_occurence(self):
		with codecs.open(self.destfolder + self.banners_file, "r", encoding="utf-8") as fin:
			bannerdic = json.load(fin)
		with codecs.open(self.reportfolder + "banner_occurence.csv", "w", encoding="utf-8") as fout:
			header = "count" + self.sep + "ip-port-time" + self.sep + "banner" + "\n"
			fout.write(header)		
			for banner in bannerdic:
				if bannerdic[banner]["count"] > 1:
					bannerstring = bannerdic[banner]["banner"]
					bannerstring = self.replace_eols(bannerstring)
					outstring = str(bannerdic[banner]["count"]) + self.sep + str(bannerdic[banner]["ip-port-time"]) + self.sep + bannerstring + "\n"
					fout.write(outstring)

	def copy_banners2probing(self):
		shutil.copy2(self.destfolder + self.banners_file, self.probingfolder + "dic-banners.json")
		
try:
	
	# shodan api and configurations
	with open('source/shodan-api-key.txt', 'r') as f:
		SHODAN_API_KEY = f.readline()
	api = shodan.Shodan(SHODAN_API_KEY)
	
	destfolder = './shodan-download/'
	inputfile = './source/ips4download.txt'
	
	# runtime action
	SD = Shodan_Downloader(api, destfolder, inputfile)
	SD.shodan_info()
	SD.user_interaction("None")
	

except:
	print(traceback.format_exc())