# -*- coding: utf-8 -*-
import re
import json
import traceback
import os
import codecs

class Vulnerability_Reporter():
# takes the shodan host downloads and parses and formats them to retrieve IP-hostname-vulnerabilities csv-report

# preconditions:	host-search files present in inputfolder from shodan-download
# postconditions:	CSV-Report in final reports folder (destfolder)

	def __init__(self, destfolder, inputfolder):
		self.destfolder = destfolder
		self.inputfolder = inputfolder
		self.pat_sep = re.compile(r'}{')
		self.attribute1 = ["ip_str", "vulns", "hostnames"]	# main attributes
		self.attribute2 = ["port", "product", "cpe", "opts"]	# data attributes
		self.csv = "~"
		
		self.checkdestfolder()
		
	def checkdestfolder(self):
		if not os.path.exists(self.destfolder):
			os.makedirs(self.destfolder)				

	def process(self):
		# create the final report from parsing json host files
		destfile = destfolder + 'report-B-vulns-99.txt'
		with codecs.open(destfile, 'w', encoding='utf8') as fout:
			col1, col2, col3 = self.attribute1
			col4, col5, col6, col7 = self.attribute2
			fout.write("?"+self.csv+col1+self.csv+col2+self.csv+col3+self.csv+col4+self.csv+col5+self.csv+col6+"\n")
			for file in os.listdir(self.inputfolder):
				current_file = os.path.join(self.inputfolder, file)
				with codecs.open(current_file, 'r', encoding='utf8') as infile:
					data = infile.readlines()
					for line in data: 
						searchresult = json.loads(line) # host info consists of main and data subinfo in which the ports are
						#print (json.dumps(searchresult, indent = 4))
						#return
						# parsing the json file
						try:
							prestring = ""
							# mark first column by ! if a vulnerability is present, $ when it was not found, and - if there is no information
							if "vulns" in searchresult:
								for vuln in searchresult['vulns']:
									if vuln.startswith('!'):
										prestring = prestring + "$"
									else:
										prestring = prestring + "!"
							else:
								prestring = prestring + "-"
							prestring = prestring + self.csv
							for colvalue in self.attribute1:
								if colvalue in searchresult:
									x = searchresult[colvalue]
									if isinstance(x, list):
										part = ','.join(map(str, x))
									else:
										part = str(x)
								else:
									part = "--"
								prestring = prestring + part + self.csv
							for port in searchresult["data"]:
								outstring = ""
								for colvalue in self.attribute2:
									if colvalue in port:
										x = port[colvalue]
										if isinstance(x, list):
											part = ','.join(map(str, x))
										else:
											part = str(x)
									else:
										part = "--"
									outstring = outstring + part + self.csv
								fout.write(prestring + outstring+"\n")
						except Exception as e:
							print (e)
							print(traceback.format_exc())

							
destfolder = './reports-99/'
inputfolder = './shodan-download/hosts/'

try:
	
	VR = Vulnerability_Reporter(destfolder, inputfolder)
	VR.process()

except:
	print(traceback.format_exc())