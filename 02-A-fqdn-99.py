# -*- coding: utf-8 -*-
import re
import json
import traceback
import os
import codecs

class FQDN_Reporter():
# takes the shodan host downloads and parses and formats them to retrieve IP-hostname-otherinfo csv-report

# preconditions:	host files present in inputfolder from shodan-download
# postconditions:	CSV-Report in final reports folder (destfolder)

	def __init__(self, destfolder, inputfolder):
		self.destfolder = destfolder
		self.inputfolder = inputfolder
		self.pat_sep = re.compile(r'}{')
		self.attribute1 = ["ip_str"] # single information in data[0]
		self.attribute2 = ["domains", "hostnames"] # multiple information in data list
		self.attribute3 = ["org", "isp"] # single information in data[0]		
		self.attribute4 = ["location.country_code", "location.postal_code", "location.city"] # single information in data[0]
		
		
		self.csv = "~"
		self.checkdestfolder()
		
	def checkdestfolder(self):
		if not os.path.exists(self.destfolder):
			os.makedirs(self.destfolder)

	def process(self):
		# create the final report from parsing json fqdn files
		destfile = destfolder + 'report-A-fqdn-99.txt'
		outstring = ""
		with codecs.open(destfile, 'w', encoding='utf8') as fout:			
			for key in self.attribute1:
				outstring += key + self.csv
			for key in self.attribute2:				
				outstring += key + self.csv
			for key in self.attribute3:				
				outstring += key + self.csv
			for key in self.attribute4:				
				outstring += key + self.csv
			fout.write(outstring + "\n")
			for file in os.listdir(self.inputfolder):
				current_file = os.path.join(self.inputfolder, file)
				with codecs.open(current_file, 'r', encoding='utf8') as infile:
					outstring = ""
					try:
						current_host = json.load(infile)
						hh = current_host["data"][0]
						#print(json.dumps(current_host, indent=4))
						#return
						# data only needed once from first data instance
						for key in self.attribute1:
							outstring += str(hh[key]) + self.csv						
						# data that can be in the banner data item but not in the first data item:											
						for key in self.attribute2:
							myset = set()
							for hh in current_host["data"]:
								myset.add(str(hh[key]))								
							outstring += str(myset) + self.csv
						# data only needed once from first data instance
						hh = current_host["data"][0]						
						for key in self.attribute3:
							outstring += str(hh[key])+ self.csv						
						for key in self.attribute4:
							at1, at2 = key.split(".")
							outstring += str(hh[at1][at2]) + self.csv
						fout.write(outstring+"\n")
					except Exception as e:
						print(traceback.format_exc())
						print("data spot:", current_host["ip_str"])
						print("data spot2:", str(hh))
						break
				
destfolder = './reports-99/'
inputfolder = './shodan-download/hosts/'

try:
	
	FQDNR = FQDN_Reporter(destfolder, inputfolder)
	FQDNR.process()

except:
	print(traceback.format_exc())