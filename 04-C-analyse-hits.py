# -*- coding: utf-8 -*-
import traceback
import json
import codecs

# after having a hits dictionary, we can analyze it.

class Hit_Checker():

	def __init__(self):
		self.sourcefolder = "./source/"
		self.workfolder = "./meltingpot/"
		self.probefolder = "./probing/"
		self.reportfolder = "./reports-99/"
		self.sep = "~"
		self.banner_dictionary_file = self.probefolder + "dic-banners.json"
		self.probes_json_file = self.probefolder + "cpe-probes.json"		
		self.hits_file = self.workfolder + "hits.json"
		
		self.hit_compare_file = self.reportfolder + "04-hit-compare.csv"
		self.nohit_file = self.reportfolder + "04-nohit.csv"
		self.nohit_json_file = self.workfolder + "04-nohit.json"
		
		self.probedic = {}
		self.bannerdic = {} 
		self.hits = {}
		
		self.load_bannerdic()
		self.load_hits()
		print(">>> Hits loaded.")	

	def load_probedic(self):
		with codecs.open(self.probes_json_file, "r", encoding="utf-8") as fin:
			self.probedic = json.load(fin)	
	
	def load_bannerdic(self):
		with codecs.open(self.banner_dictionary_file, "r", encoding="utf-8") as fin:
			self.bannerdic = json.load(fin)
	
	def load_hits(self):
		with codecs.open(self.hits_file, "r", encoding="utf-8") as fin:
			lines = fin.readlines()
			for line in lines:
				hit = json.loads(line)
				self.hits[hit["banner"]] = hit
			
	def load_portmapper(self):
		with codecs.open(self.portmap_file, 'r', encoding="utf-8") as infile:
			self.portmapper = json.load(infile)

	def compare_hits_shodancpes(self):
		# hits: compare cpes with shodan-cpes
				
		with codecs.open(self.hit_compare_file, "w", encoding="utf-8") as fout:
			
			fout.write("count~banner-hit-hash~probe~ports~cpe~shodancpe\n")
			ident_count = 0
			strong_count = 0
			level2hits = 0
			for hit in self.hits:
				outstring = ""
				hhit = self.hits[hit]						
				
				hash = hit
				banner = self.bannerdic[hash]
				# only count but not print identical
				if hhit["cpe"] == banner["shodan-cpes"]:
					ident_count += 1
					continue
					
				# do not list the ones lower than version number:
				has_version = False
				for cpe in hhit["cpe"]:
					if cpe.count(":") > 3:
						has_version = True
					else:
						level2hits += 1
				if not has_version:
					continue
				
				# we count the openssh hits as identical, there is only a minor difference in linux os identification
				is_openssh = False
				for cpe in hhit["cpe"]:
					if cpe[:22] == "cpe:/a:openbsd:openssh":
						ident_count += 1
						is_openssh = True
				if is_openssh:
					continue
				
				# a strong advantage is when we got a version hit and shodan got nothing:
				if not banner["shodan-cpes"]:
					strong_count += 1
				
				output = []
				output.append(hhit["count"])
				output.append(hash)
				output.append(hhit["probe"])
				output.append(hhit["ports"])
				
				output.append(hhit["cpe"])
				output.append(banner["shodan-cpes"])
				for entry in output:
					outstring += str(entry) + self.sep
				fout.write(outstring + "\n")
			fout.write("identical cpes were skipped, #:" + str(ident_count) + "\n")
			fout.write("hits with only 2-level cpes were skipped:, #:" + str(level2hits) + "\n")
			fout.write("hit with version but shodan empty, #:" + str(strong_count) + "\n")			
		print(">>> Wrote difference-in-hits file:", self.hit_compare_file)
				
		# banners with shodan-cpes that were not hit
		missed = 0
		nohits = []
		with codecs.open(self.nohit_file, "w", encoding="utf-8") as fout:			
			fout.write("banner~ports~shodancpe\n")
			for banner in self.bannerdic:
				outstring = ""
				bbanner = self.bannerdic[banner]
				if bbanner["shodan-cpes"]:
					scpes = bbanner["shodan-cpes"]
					
					hhits = self.hits.get(banner, None)	# return None if key is not in dictionary						
					if hhits is None:					
						missed += 1
						nohits.append(banner)
						output = []
						output.append(banner)
						output.append(bbanner["ports"])
						output.append(scpes)
						for entry in output:
							outstring += str(entry) + self.sep
						fout.write(outstring + "\n")
			fout.write("count, #:" + str(missed) + "\n")
		print(">>> Wrote missed shodan-cpes file:", self.nohit_file)
		with codecs.open(self.nohit_json_file, "w", encoding="utf-8") as fout:
			json.dump(nohits, fout)
		print(">>> Wrote nohits json file:", self.nohit_json_file)
				
	def test(self):
		my = set()
		for banner in self.bannerdic:
			my.add(banner)
		print("Consistency check on banners: if banners are unique, counts equal: " + str(len(self.bannerdic)) + " vs. " + str(len(my)) )
		
try:

	HC = Hit_Checker()
	HC.compare_hits_shodancpes()
	HC.test()

except:
	print(traceback.format_exc())