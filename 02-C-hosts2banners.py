# -*- coding: utf-8 -*-
import traceback
import sys
import os
import hashlib
import codecs
import json

class Hosts2Banners():

# taking the host file information and merging any missing data into the banners file.

	def __init__(self):
			
		self.probingfolder = "./probing/"						
		self.banners_file = "dic-banners.json"
		self.inputfolder = "./shodan-download/hosts/"
	
	def hosts2banners(self):
		present_banners = 0
		present_but_ip_port = 0
		new_banners = 0
		# check if banner file is present, if not, this is a hosts-only search.
		file_path = os.path.join(self.probingfolder, self.banners_file)
		if os.path.isfile(file_path):	
			with codecs.open(self.probingfolder + self.banners_file, "r", encoding="utf-8") as fin:
				bannerdic = json.load(fin)
		else:
			bannerdic = {}
		# loop through the host files
		for file in os.listdir(self.inputfolder):
			current_file = os.path.join(self.inputfolder, file)
			print(current_file)
			with codecs.open(current_file, 'r', encoding="utf-8") as infile:			
				try:
					current_host = json.load(infile)
					banners = current_host["data"]
					for bbanners in banners:						
						hash = hashlib.md5(bbanners["data"].encode('utf8')).hexdigest()					
						xxbanner = bannerdic.get(hash, None)	# return None if key is not in dictionary						
						if xxbanner:
							present_banners += 1
							port = bbanners["port"]
							# there are doubles because of timestamp, we just take a count if ip and port were different.
							if not bbanners["ip_str"] in xxbanner["ips"]:
								if not port in xxbanner["ports"]:
									xxbanner["ips"].append(bbanners["ip_str"])
									xxbanner["ports"].append(port)
									ip_port = (bbanners["ip_str"], bbanners["port"], bbanners["timestamp"])
									xxbanner["ip-port-time"].append(ip_port_time)									
									xxbanner["count"] += 1
									present_but_ip_port += 1
							if "cpe" in bbanners:
								for cpe in bbanners["cpe"]:
									# remove trailing slash /$ for better comparison
									if cpe[-1:] == "/":
										cpe = cpe[:-1]
						else:							
							newbanner = {}						
							newbanner["hash"] = hash
							newbanner["ports"] = []
							newbanner["ports"].append(bbanners["port"])
							newbanner["ips"] = []
							newbanner["ips"].append(bbanners["ip_str"])
							newbanner["ip-port-time"] = []
							ip_port_time = []
							ip_port_time = (bbanners["ip_str"], bbanners["port"], bbanners["timestamp"])						
							newbanner["ip-port-time"].append(ip_port_time)
							newbanner["probe-hitlist"] = []
							newbanner["banner"] = bbanners["data"]
							newbanner["banner-length"] = len(bbanners["data"])
							newbanner["count"] = 1
							newbanner["shodan-cpes"] = []
							if "cpe" in bbanners:
								for cpe in bbanners["cpe"]:
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
							new_banners += 1
				
				except Exception as e:
					print(traceback.format_exc())
					print("data spot:", current_host["ip_str"])					
					break
		
		print(">>> Banner dictionary updated:", str(present_banners), " were already included, ", str(new_banners), " have been added.")
		print(">>> From the included, these were updated by unique ip-port instances:", str(present_but_ip_port))		
		
		with codecs.open(self.probingfolder + self.banners_file, "w", encoding="utf-8") as fout:
			json.dump(bannerdic, fout)	
		
try:
	
	# runtime action	
	H2B = Hosts2Banners()
	H2B.hosts2banners()	

except:
	print(traceback.format_exc())