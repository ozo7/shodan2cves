# -*- coding: utf-8 -*-
import re
import json
import traceback
import os
import sys
import hashlib
import codecs

#- get match lines from source and divide into cpe, product and nmap service name only
#=> count report
#- presort to known ports and probes without ports to "unknown ports"
#=> these are the json portfiles
#- prepare the portfiles for probing against shodan banners
#=> they have been prepared in the cpe-probes.json file , each probe has a unique hash and a port attribute

# List of found regex peculiarities, the nmap service probes regex are in Perl-format.
# Regex have been tested in /basic example scripts
#	/s 						means that . also matches newline
#	^(?=.*\bsecond\b)		positive lookahead to make sure to have the word "second" in the searched string
#	(?:\|.+?){2}(?:\|).+?(wor)		this looks for as many | as specified in {2}, then looks for the next while not memorizing the reference groups of these matches, and finally takes the first occurence of(wor) into a reference group.

class Probes_Preparer():

# preconditions:
#	nmap-service-probes file in source
#	nmap-servicename2port.json in source, for port to nmap service name mapping
# postconditions:
#	produces distribution files, especially the cpe regex matching probes
#	produces the json probes file that contains the enriched probe data
#	produces the json port files for more efficient banner matching processes

	def __init__(self, destfolder, inputfolder):
		self.destfolder = destfolder
		self.inputfolder = inputfolder
		self.pat_cpe = re.compile(r'cpe:[/,|]')
		self.pat_match = re.compile(r'match ')
		self.pat_softmatch = re.compile(r'softmatch ')
		self.pat_product = re.compile(r'p[/.+/,|.+|]')
		self.pat_servicename = re.compile(r'(?:soft)?match (.+?) m(.{1})')	# gets the nmap servicename between "match" and "m" in group 1 and the regex delimiter in group 2
		self.pat_final_linebreaks = re.compile(r'\\r\\n$')
		self.probefile = inputfolder + "nmap-service-probes"
		self.portmapfile = inputfolder + "nmap-servicename2port.json"
		self.cpefile = destfolder + "cpe-probes.txt"
		self.productfile = destfolder + "product-probes.txt"
		self.servicenamefile = destfolder + "servicename-probes.txt"
		self.distributioncounters = {}
		self.distributioncounters["cpe"] = 0
		self.distributioncounters["product"] = 0
		self.distributioncounters["servicename"] = 0
		self.probes_json_file = destfolder + "cpe-probes.json"
		self.subdirs = ("portfiles/",)
		
		self.checkdestfolder()
		
	def checkdestfolder(self):
		if not os.path.exists(self.destfolder):
			os.makedirs(self.destfolder)
		for subdir in self.subdirs:
			directory = destfolder + subdir
			if not os.path.exists(directory):
				os.makedirs(directory)
				
	def cleanupfiles(self): # check: only subdirectories?
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
					
	def count_lines_directory(self, folder):
		counter = 0
		for the_file in os.listdir(folder):
			file_path = os.path.join(folder, the_file)
			if os.path.isfile(file_path):
				with open(file_path, 'r') as f:
					for line in f:
						counter += 1
		return counter
		
	def get_baseprobes(self):
		# distribute nmap source probes to distribution files cpe, product, servicename
		with codecs.open(self.probefile, "r", encoding="utf-8") as fin:
			with codecs.open(self.cpefile, "w", encoding="utf-8") as fcpe:
				with codecs.open(self.productfile, "w", encoding="utf-8") as fproduct:
					with codecs.open(self.servicenamefile, "w", encoding="utf-8") as fservicename:
						data = fin.readlines()
						for line in data:
							if self.pat_match.match(line) or self.pat_softmatch.match(line):
								if self.pat_cpe.search(line):
									fcpe.write(line)
									self.distributioncounters["cpe"] += 1
								elif self.pat_product.search(line):
									fproduct.write(line)
									self.distributioncounters["product"] += 1
								else:
									fservicename.write(line)
									self.distributioncounters["servicename"] += 1
		# sort the cpe file for easier processing afterwards
		# also, add regex delimiter info at the beginning
		os.rename(self.cpefile, self.cpefile + ".old")
		newcpefile = codecs.open(self.cpefile, "w", encoding="utf-8")
		with codecs.open(self.cpefile + ".old", "r", encoding="utf-8") as fcpe:
			lines = fcpe.readlines()
			for line in lines:
				groupmatch = self.pat_servicename.match(line)
				#currentservicename = groupmatch.group(1)
				regex_delimiter = groupmatch.group(2)
				line = regex_delimiter + line
				newcpefile.write(line)
		newcpefile.close()
		os.unlink(self.cpefile + ".old")
		lines = ""
		with codecs.open(self.cpefile, "r", encoding="utf-8") as fcpe:
			lines = fcpe.readlines()
			lines.sort()
		with codecs.open(self.cpefile, "w", encoding="utf-8") as fcpe:
			fcpe.write("".join(lines))
		# print the distribution counters
		print ("Distribution result: ")
		for key, value in self.distributioncounters.items():
			print (key, ":\t", value)

	def parse_cpefile2json(self):

		def make_probelist_unique(probe_json_dictionary_list, firstcall):
			# consistency check for uniqueness of list by hash:
			compareset = set()
			diffset = set()
			for probe in probe_json_dictionary_list:
				if probe["hash"] not in compareset:
					compareset.add(probe["hash"])
				else:
					diffset.add(probe["hash"])
			if len(compareset) == len(probe_json_dictionary_list):
				print(len(compareset),"versus",len(probe_json_dictionary_list))
				print(">>> OK. probe list is unique.")
			else:
				if not firstcall:
					raise "!!! Could not clean doubles in probelist." 
				print(len(compareset),"versus",len(probe_json_dictionary_list))
				print("! probe list is not unique. Cleaning up.") # the double entries are due to the nmap probe file structure. They recomment ports and as of August 2015, there were 27 probes that were double in the file.
				
				# print difference probes to file
#				zzoutfile = "zz-diff-probes.json"
#				with open(destfolder + zzoutfile, "w") as fout:
#					for probe in probe_json_dictionary_list:
#						if probe["hash"] in diffset:
#							fout.write(json.dumps(probe) + "\n")
#				print("!!! check: ", destfolder + zzoutfile)

				# clean list up by using indices
				iindex = 0
				compareset = set()
				while iindex < len(probe_json_dictionary_list):
					probe = probe_json_dictionary_list[iindex]
					if probe["hash"] not in compareset:
						compareset.add(probe["hash"])
						iindex = iindex + 1
					else:
						# remove the elemtent by index
						probe_json_dictionary_list.pop(iindex)
				probe_json_dictionary_list = make_probelist_unique(probe_json_dictionary_list, False)

			return probe_json_dictionary_list

		def create_line_dic(line):
			# do the line parsing, process and shorten the line from the beginning
			# get the regex and remainder
			regex = '\|(?:soft)?match (.+?) (?:(.)\|)(.+?)\|(:?.)(.+)'
			# regex_delimiter
			# data has different regex-delimiter, take care of that:
			regex_delimiter = line[0]
			if regex_delimiter != '|':
				regex = re.sub(r"\|", regex_delimiter, regex)
			xx_regexx =  r"" + regex + r""
			try:
				groupmatch = re.search(xx_regexx, line, flags=re.DOTALL) # make the . also match new line characters
				# there should be 4 group matches
				linedic = {}
				linedic["delimiter"] = regex_delimiter
				linedic["servicename"] = groupmatch.group(1)
				linedic["prefix"] = groupmatch.group(2)
				# the original file contains bad linebreaks at the end of the regex. remove it.
				fineregex = re.sub(self.pat_final_linebreaks, r'', groupmatch.group(3))
				linedic["regex"] = fineregex
				linedic["postfix"] = groupmatch.group(4)
				# now parse the remainder
				remainder = groupmatch.group(5)
				# regex_remainder = '(?:p\/(.+?)\/)?(?:.)?(?:v\/(.+?)\/)?(?:.)?(?:i\/(.+?)\/)?(?:.)?(?:o\/(.+?)\/)?(?:.)?(cpe.+)'
				# awful, but regex part \/ war replaced by [\/,\|] because things like o|z/VM $2|   <= there is a slash in the name of the os
				regex_remainder = '(?:p[\/,\|](.+?)[\/,\|])?(?:.)?(?:v[\/,\|](.+?)[\/,\|])?(?:.)?(?:i[\/,\|](.+?)[\/,\|])?(?:.)?(?:o[\/,\|](.+?)[\/,\|])?(?:.)?(cpe.+)'
				xx_regexx =  r"" + regex_remainder + r""
				groupmatch = re.search(xx_regexx, remainder, flags=re.DOTALL)
				linedic["product"] = groupmatch.group(1)
				linedic["version"] = groupmatch.group(2)
				linedic["i"] = groupmatch.group(3)
				linedic["os"] = groupmatch.group(4)
				# if there is more than one cpe, there is a space inbetween
				linedic["cpe"] = []
				ccpe = groupmatch.group(5).rstrip().split(" ")
				for cccpe in ccpe:
					# remove trailing slash /$ for better comparison
					if cccpe[-1:] == "/":
						cccpe = cccpe[:-1]
					# remove trailing slash /a for better comparison, it is like this in the source file
					if cccpe[-2:] == "/a":
						cccpe = cccpe[:-2]
					linedic["cpe"].append(cccpe)
				# finally create a hash for recognition
				linedic["hash"] = hashlib.md5(linedic["regex"].encode('utf8')).hexdigest()
				
				# for the saving to a csv-file:
				#csv = "~"
				#print (linedic["delimiter"], csv, linedic["servicename"], csv, linedic["prefix"], csv, linedic["postfix"], csv, linedic["product"], csv, linedic["version"], csv, linedic["i"], csv, linedic["os"], csv, linedic["cpe"], csv, linedic["regex"])
								
			except:
				print(traceback.format_exc())
				print(">>> Regex: \n", regex)
				print(">>> Line: \n", line)
				print(">>> Regex Remainder: \n", regex_remainder)
				print(">>> Remainder: \n", remainder)
				sys.exit(0)
			
			return linedic

				
		# process the cpe-file and put it into a data structure for json
		probe_json_dictionary_list = []
		with codecs.open(self.cpefile, "r", encoding="utf-8") as fcpe:
			lines = fcpe.readlines()
			for line in lines:
				try:
					linedic = create_line_dic(line)
				except:
					print(traceback.format_exc())
					break
				probe_json_dictionary_list.append(linedic)
			# tidy up the probelist:
			#	- if some element in a list is empty, we prefer to set it to None
			#	- references: tupel of keys that need backreference from regex, check for $: product, version, info, os, cpe
			#	- prepare attributes port-hitlist and banner-hitlist
			#	- create the port attribute from the portmapper configuration file
			for probe in probe_json_dictionary_list:
				if (probe["postfix"]) == " ":	# only these were found in "postfix", other keys are ok and have None
					probe["postfix"] = None
				re_pat = re.compile(r"\$")
				zzref = []
				for xx in ("product", "version", "i", "os", "cpe"):
					if re.search(re_pat, str(probe[xx])):
						zzref.append(xx)
				probe["zzref"] = zzref
				probe["port-hitlist"] = []
				probe["banner-hitlist"] = []
				probe["ports"] = []
				with codecs.open(self.portmapfile, 'r', encoding="utf-8") as infile:
					portmapper = json.load(infile)
					if probe["servicename"] in portmapper:
						probe["ports"] = portmapper[probe["servicename"]]
			# there might be more to do in the future here... like tidying up the regex itself.
			
			
			# check and remove doubles in list
			probe_json_dictionary_list = make_probelist_unique(probe_json_dictionary_list, True)
			
			# create a probe dictionary by hash
			probedic = {}
			for probe in probe_json_dictionary_list:
				probedic[probe["hash"]] = probe				

			# save the probedic to json:
			with codecs.open(self.probes_json_file, "w", encoding="utf-8") as fout:
				json.dump(probedic, fout)
					
	def create_portfiles(self):
		# open json probe file
		with codecs.open(self.probes_json_file, "r", encoding="utf-8") as probefile:
			probedic = json.load(probefile)
			for probe in probedic:
				if len(probedic[probe]["ports"]) > 0:
					for p in probedic[probe]["ports"]:
						with codecs.open(self.destfolder + self.subdirs[0] + "p" + str(p) + ".json", "a", encoding="utf-8") as fout:
							json.dump(probedic[probe], fout)
							fout.write("\n")
				else:
					with codecs.open(self.destfolder + self.subdirs[0] + "p" + ".json", "a", encoding="utf-8") as fout:
						json.dump(probedic[probe], fout)
						fout.write("\n")

# ! probes delta update not relevant now
# Changes by probes identified with hashes with large collision
# ! check: cpe to spot old windows systems
# check: manually edit portmapper file?

inputfolder = "./source/"
destfolder = "./probe-prepare/"

try:

	PP = Probes_Preparer(destfolder, inputfolder)
	PP.get_baseprobes()
	PP.parse_cpefile2json()		# there is tricky regex handling here, watch out for errors.
	PP.cleanupfiles()
	PP.create_portfiles()
	
except:
	print(traceback.format_exc())