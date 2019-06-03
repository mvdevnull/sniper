#!/usr/bin/python
####
#
#	RAWR - Rapid Assessment of Web Resources
#	         Written 2012 by Adam Byers  (@al14s)
#                   al14s@pdrcorps.com
#
####
# 
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details. 
#
####
#
#    Romans 5:6-8
#
####
#
#		Special thanks to:  
#			c0ncealed					Testing, Functional/Practical input
#			can0beans					Project Direction, Functional/Practical input
#			_fmm						Info Gathering, Testing
#			Artis Schlossberg				Testing, 'pull SSL data' suggestion, functional input
#			human39						Testing, functional input
#			justbill					Testing, functional input
#			fyodor						for NMap and scanme.nmap.org   ;)
#			WEBNet77.net					for countrytoIP resolution
#			Ariya Hidayat					phantomJS - an awesome headless Webkit
#
####
#
#	  	Exit codes:		0 - Normal Exit
#						1 - Exit with error
#						2 - User Initiated Exit
#
###

import os
import shutil
import operator
import glob
import getopt
import sys
import re
import time
import urllib2
import threading
import tarfile
import Queue
import socket
import signal
import platform
import subprocess
import httplib
import fileinput
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom

version = "0.1.4"

banner = """             
                                                    , `.
 `.////.                  .     -+/s.            +ho+oo-o`
 s/`  `o-   o+`    -      s.  `o:  o-         -sddo//+sydhys/:'.
 //   .o`  `s/o`   o.  `  +:  /+...o/      .smd+.   `/o+.`-ymoo,
 `s`:+/`   :o /o-` :+ .s+`:+   -/s+/+    `omy-     :mh-om/  -dh//:.
  :s:://.  o/:--s-  o.o--o-s   .o. .s   `hh.       hddydNy    od.o /
  `s`  `-+ +    `/: .ss  `oy` .o`  `s  `ds  -.     `+yhy+`     od-.
   o.     `          ``    .  :-    `  ym `moy.   `..-:///:/` `N/-
                                      :M+ .yhy+-.,/:--/o\ /d`  om/`',
                                      -M:  .'-/+:symdyysy+oN+  .N+:-
   Rapid Assessment of Web Resources   dd  .h/hyhddMms+:-/./m   dy-
                                       /M-  -NmmNhms`     ``m`  sd.;.
            [Version %s]            `Ms   mNmNN+       s/y   oNoyM:
                                   ,os+-mh   /mymm :./+:/+s+/ :hs``mM-
                                   +y.:omN`  -o:dso/o:+::.   `oh-  +My
                                    /h:`oM-                  ``   :Nd
                                     .yyyM/                     `+Nh`
         by Adam Byers (@al14s)        -hMo     .:++:/.         `/hm::
                                        .Ny   .o/-------.         oN:-
           al14s@pdrcorps.com           `Ny   s..`..-...+ `/+     :N/-:`
                                       `oMy   o.`....```-/h/.    `-:ooy/-:`
                                       d/Ny   /...``...//N`           `:+o:.-
                                      .N`N/   ./.`.----:sd                 -/o
                                     oo/.d-  `./-o+++-:mh/.```:-````-:+sys+:.

"""%version

usage = """
 Usage: 
   ./rawr.py [-n <range> (-p <ports> -s <port> -t <timing>)|-f <xml>|-i <list>]
                   [-d <dir>] [--sslv] [-aboqrz] [--downgrade]
                     [-e] [--title <title>] [--logo <file>]
                    [-u|-U] [--check-install|--force-install]

   INPUT/SCAN OPTIONS:
    -a      Include all open ports in .csv, not just web interfaces.
    -f      NMap|Nessus|Nexpose|Qualys xml or dir from which to pull files.
    -i      Target an input list.  [NMap format] [can't be used with -n]
    -n      Target the specified range or host.  [NMap format]
    -p      Specify port(s) to scan.   [default is '80,443,8080,8088']
    -s      Specify a source port for the NMap scan.
    -t      Set a custom NMap scan timing.   [default is 4]
    --sslv  Assess the SSL security of each target.  [considered intrusive]


   ENUM OPTIONS:
    -b      Use Bing to gather external hostnames. (good for shared hosting)
    -o      Make an 'OPTIONS' call to grab the site's available methods.
    -r      Make an additional web call to get 'robots.txt'
    --downgrade  Make requests using HTTP 1.0


   OUTPUT OPTIONS:
    -d      Logging Directory [default is './log_[date]_[time]_rawr']
    -h      Show this info + summary + examples.
    -q      'quiet' - Won't show splash screen.
    -z      Compress log folder when finished.


   REPORT OPTIONS:
    -e       Exclude default username/password data from output.
    --title  Specify a custom title for the HTML report.
    --logo   Specify a logo file for the HTML report.


   UPDATE OPTIONS:
    -u      Check for newer version of IpToCountry.csv and defpass.csv.
    -U      Force update of IpToCountry.csv and defpass.csv.

    --check-install  Check for newer IpToCountry.csv and defpass.csv,
                     Check for presence of NMap and its version.
                     Check for presence of phantomJS, prompts if installing.

    --force-install  Force update - IpToCountry.csv, defpass,csv, phantomJS.
                     Check for presence of NMap and its version.
"""

summary = """

   SUMMARY:

         Uses NMap, Qualys, Nexpose, or Nessus scan data to target web
             services for enumeration. Visits each host on each port with an
             identified web service and gathers as much data as possible.  


         Output:  
              All NMap output formats (xml uses local copy of nmap.xsl)
              CSV worksheet containing all collected info.
              HTML report  (searchable, jQuery-driven, standalone)
              Images folder  (contains screenshots of the web interfaces)
              Cookies folder
              SSL Certificates folder

         Usage diagram:

         .--LOG          --.   .--SCAN                          --.
         | ./log_[dt]_rawr/ |  | -a include all results in csv    |
         | -z .tar file      > | -f nmap or nessus xml (or dir)   |
         | -d log directory |  | -i use an input list for NMap    |
         `--              --'  | -n nmap <range>                   > [xml data]
                               |     (-p <ports>,-t <timing>)     |      .
                               |      (-s <source port>)          |      |
                               `--                              --'      |
                                    .------------------------------------'
                                    |
         .--SUPPLEMENT         --.  |   .--ENUMERATE                     --.
         | IpToCountry.csv &     |  `-> |      Web service enumeration     |
         |   defpass.csv         |      | --downgrade  use HTTP 1.0         --.
         | -u|-U to update from   ----> | --sslv [intrusive] SSL assessment|  |
         |    the SF page or     |      | -r make call for robots.txt      |  |
         | -e to exclude defpass |      | -o Pull available methods        |  |
         | -b use Bing for DNS   |      `--                              --'  |
         | --title report title  |          .---------------------------------`
         | --logo  report logo   |          |
         `--                   --'          |   .--OUTPUT      --.
                                            |   | CSV worksheet  |
                                            |   | HTML report    |
                                            `-> | NMap output     >    :)
                                                | Cookies        |
                                                | Screenshots    |
                                                | SSL certs      |
                                                | Robots.txt     |
                                                `--            --'"""        

examples = """


   EXAMPLES:

     ./rawr.py -n scanme.nmap.org
          Use a generic logging directory ( ./log_[date]_[time]_rawr )

     ./rawr.py -n www.google.com -p all
          Pull data from web services found on any of the 65535 ports.

     ./rawr.py -f previous_nmap_scan.xml --sslv
          Use targets from a previous nmap scan, assessing the server's
            SSL security state.

     ./rawr.py -d scanfolder -n scanme.nmap.org -p 80,8080 -e
          Pull additional data about the server/site and its SSL cert from
            ports 80 and 8080, excluding default password data.  
            Stores results in ./scanfolder .

     ./rawr.py -i nmap_inputlist.iL -p fuzzdb -b -z
          Use an input list, checking the fuzzdb 'common web ports'.  
            Compress results into a .tar file.
            Use Bing to resolve DNS names of hosts.

     ./rawr.py -u
          Update 'Ip to Country' and 'default password' lists from the
            BitBucket repo.


"""

files = []
binged = []
binging = False
nmapout = ""
nmap_il = ""
sslopt = ""
nmaprng = ""
sourceport = ""
logo_file = ""
logdir = None
quiet = False
defpass = True
newdir = False
xmlfile = False
compress_logs = False
bing_dns = False
ckinstall = False
getRobots = False
getoptions = False
ver_dg = False
allinfo = False


#######################################
#    Settings                         #
#######################################
report_title = "Web Interface Enumeration Results"	# default title if '--title' is not specified
timeout = 20        # timeout in seconds for each web call (screenshots and geturl)
ss_delay = 1        # delay in seconds or page to render before screenshot
nmapspeed = 4       # nmap
nthreads = 25       # number of threads for the info run
useragent = 'Mozilla/5.0 (Windows NT 5.1; rv:8.0) Gecko/20100101 Firefox/7.0'	# u-agent for the info run and screenshots.  This is sensitive - SS function might not work if this is invalid!
#http://code.google.com/p/fuzzdb/source/browse/trunk/wordlists-misc/common-http-ports.txt
fuzzdb = "66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8080,8888,30821"
ports = "80,443,8080,8088,8443"	 # default scan ports
csv_sort_col = "host_ip"     # The column name of the field by which the CSV will be ordered.  *Must exist in 'flist'*
flist = "url, host_ip, port, returncode, hostname, notes, Title, version, allow, cookies, SSL_Cert-KeyAlg, SSL_Tunnel-Ciphers, SSL_Tunnel-Weakest, SSL_Cert-DaysLeft, SSL_Cert-ValidityPeriod, SSL_Cert-MD5, SSL_Cert-SHA-1, SSL_Cert-notbefore, SSL_Cert-notafter, state, protocol, country, service, robots.txt, rpc_info, endURL, Date, Server, analytics_ID, owner, Content-MD5, Content-Type, Last-Modified, Trailer, Transfer-Encoding, Warning, X-XSS-Protection, X-Frame-Options, WWW-Authenticate, Proxy-Authenticate, Age, Robots, Keywords, Description, Author, Revised, form_start, passwordFields, emailAddresses, HTML5, info, Default Password Suggestions"
# 'flist' contains the column headers for the csv generated post-scan.  Add, Rearrange, or Remove fields as desired.
#		Tip: 'notes' is not a field used in html headers and will contain no data, so it can be used for entering notes during followup.
# DISABLED COLUMNS (use the line below to store columns you don't want to see in the csv):
# 	SSL_Tunnel-CiphersRaw, SSL_Cert-Raw, SSL_Cert-Subject, SSL_Cert-Verified, SSL_Cert-Issuer, Cache-Control, Connection, Content-Encoding, Content-Language, Content-Length, meta, Content-Location, 
#######################################
#                                     #
#######################################


class out_thread(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.queue = queue
		global writelog

	def run(self): 
		while True:
			writelog(self.queue.get())
			self.queue.task_done()
					

class sithread(threading.Thread):
	def __init__(self):
		threading.Thread.__init__(self)
		global q
		global opener
		self.q = q
		self.terminate = False
		self.busy = False
		self.opener = opener

	def run(self):
		global threads
		global binged
		global binging

		while not self.terminate:
			time.sleep(0.5)
			if not self.q.empty():
				data = ""
				self.busy = True
				nmap = self.q.get().split(', ')

				hostnames = []

				prefix = "http://"
				if any(s in nmap[6] for s in ["https","ssl"]):
					prefix = "https://"
					
				suffix = ":"+nmap[2]
				if any(s in nmap[2] for s in ["80","443"]):
					suffix = ""
				
				if bing_dns == True and not "bing~" in nmap[0]:
					# Don't do Bing>DNS lookups for non-routable IPs
					routable = True		
					nrips = ["10.","172.","192.168.","127.;16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31","169."]
					for nrip in nrips:
						if nmap[0].startswith(nrip.split(";")[0]):
							if len(nrip.split(";")) > 1: 
								for subnet in nrip.split(";")[1].split(","):
									if nmap[0].startswith(nrip.split(";")[0]+subnet+'.'):
										routable = False
							else:
								routable = False

					if routable:
						while binging:
							time.sleep(0.5)

						binging = True

						if nmap[0] in "~".join(binged):
							output.put("[@] Bing>DNS\t: "+nmap[0]+"  -  pulling from cache...")
							for item in binged:
								if nmap[0] in item.split(":")[0]:
									hn = item.split(":")[1].split(";")									
									if len(hn) != 0 and hn[0] != "":
										hostnames = hn

									break
						else:
							self.opener.addheaders.append(('Cookie', 'SRCHHPGUSR=NRSLT=150'))

							output.put("[@] Bing>DNS\t: "+nmap[0])
							try: 
								bing_res = self.opener.open(("http://www.bing.com/search?q=ip%3a"+nmap[0])).read().split("sb_meta")
								for line in bing_res:
									res = re.findall( r".*<cite>(.*)</cite>.*", line )
									if res:
										hostnames.append(res[0].split('/')[0])

								binged.append(nmap[0]+":"+";".join(hostnames))
							except Exception, ex: 
								output.put("[x] Bing>DNS\t: Error - %s"%ex)
								hostnames = []

						binging = False

						# back to normal
						self.opener.addheaders = [('User-agent', useragent)]

						if len(hostnames) == 0: 
							output.put("[x] Bing>DNS\t: found no DNS entries for %s"%(nmap[0]))
						else:
							# remove any duplicates...
							seen = set()
							hostnames = [ x for x in hostnames if x not in seen and not seen.add(x)]
							output.put("[+] Bing>DNS\t: found %s DNS entries for %s"%(len(hostnames),nmap[0]))
							for hostname in hostnames[1:]:
								self.q.put("bing~"+nmap[0]+", "+hostname+"|"+", ".join(nmap[1:]))

							hostnames = [hostnames[0]]
					else:
						output.put("[-] %s is not a routable IP, skipping Bing>DNS for this host."%nmap[0])


				# Add the ip into the mix of hostnames
				if "bing~" in nmap[0]:
					hostnames = [nmap[1].split('|')[0]]
					nmap[0] = nmap[0].split('~')[1]
				else:
					for item in nmap[1].split('|'): 
						if item != "":
							hostnames.append(item)

					hostnames.append(nmap[0]) 

				for hostname in hostnames:
					if hostname != "":
						url = prefix+hostname+suffix
						if suffix == "":
							port = " ["+nmap[2]+"]"
						else:
							port = ""

						output.put("[>] Pulling\t: "+url+port)

						screenshot(url,hostname,nmap[2])

						try:
							data = self.opener.open(url)
							msg = "[+] Finished"
						except Exception, ex:
							if hasattr(ex, 'code'):
								e = ex.code
							elif hasattr(ex, 'reason'):
								e = ex.reason
							else:
								e = ex

							msg = "[x] Failed"
							# last ditch effort to try and snag the error info
							try:
								data = e
							except:
								pass

						parsedata(data,url+', '+', '.join(nmap))
						output.put(msg+"\t: "+url+port)

				self.busy = False

				busy_count = 0
				for t in threads:
					if t.busy == True:
						busy_count += 1
	
				output.put(" [ Queue size [ %s ] - Threads Busy/Alive [ %s/%s ] ] "%(str(self.q.qsize()),busy_count,str(threading.active_count()-2)))

				self.q.task_done()


def screenshot(url, ip, port):
	global logdir
	global scriptpath
	global pjs_path
	global output
	global useragent
	global timestamp
	global ss_delay
	global timeout

	filename = "%s/images/%s_%s.png" % (logdir,ip,port)
	err='.'
	try:
		log_pipe = open("%s/rawr_%s.log"%(logdir,timestamp),'ab')
		start = datetime.now()
		process = subprocess.Popen([pjs_path,"--web-security=no","--ignore-ssl-errors=yes","--ssl-protocol=any",scriptpath+"/screenshot.js",url,filename,useragent,str(ss_delay)], stdout=log_pipe, stderr=log_pipe)
		while process.poll() is None:
			time.sleep(0.1)
			now = datetime.now()
			if (now - start).seconds > timeout+1:
				sig = getattr(signal, 'SIGKILL', signal.SIGTERM)
				os.kill(process.pid, sig)
				os.waitpid(-1, os.WNOHANG)
				err=' - Timed Out.'
				break

		log_pipe.close()
		log_pipe = None
		process = None

		if os.path.exists(filename): 
			if os.stat(filename).st_size > 0:
				output.put('[>] Screenshot\t: [ %s ] >>\n   %s' % (url,filename))
			else:
				output.put('[X] Screenshot\t: [ %s ] Failed - 0 byte file. Deleted.' % (url))
				try:
					os.remove(filename)
				except:
					pass
		else:
			output.put('[X] Screenshot\t:  [ %s ] Failed%s' % (url,err))

	except Exception, ex:
		output.put('[!] Screenshot\t:  [ %s ] Failed - %s' % (url,ex))



def addtox(fname,val): 
	if fname.lower() in flist.lower():
		x[flist.lower().split(", ").index(fname.lower())] = re.sub('[\n\r,]', '', str(val))


def parsedata(data,nmap):
	global logdir
	global output

	x=[" "] * len(flist.split(","))

	def addtox(fname,val): 
		if fname.lower() in flist.lower():
			x[flist.lower().split(", ").index(fname.lower())] = re.sub('[\n\r,]', '', str(val))

	addtox("url", nmap.split(", ")[0])
	addtox("host_ip", nmap.split(", ")[1])
	addtox("hostname", nmap.split(", ")[2])
	addtox("port", nmap.split(", ")[3])
	addtox("state", nmap.split(", ")[4])
	addtox("protocol", nmap.split(", ")[5])
	addtox("owner", nmap.split(", ")[6])
	addtox("service", nmap.split(", ")[7])
	addtox("rpc_info", nmap.split(", ")[8])
	if len(nmap.split(", ")) > 9:
		addtox("version", nmap.split(", ")[9])

	# identify country if possible
	if os.path.exists("%s/IpToCountry.csv"%scriptpath):
		ip = nmap.split(", ")[1].split('.')
		ipnum = (int(ip[0])*16777216) + (int(ip[1])*65536) + (int(ip[2])*256) + int(ip[3])
		for l in re.sub('[\"\r]', '', open("%s/IpToCountry.csv"%scriptpath).read()).split('\n'):
			try:
				if l != "" and (not "#" in l) and (int(l.split(',')[1]) > ipnum > int(l.split(',')[0])):
					addtox("country","[%s]-%s"%(l.split(',')[4],l.split(',')[6])); break
			except Exception, ex:
				output.put("  -- Error parsing IpToCountry.csv:  %s  --"%ex)

	if getoptions:
		try:
			req = urllib2.Request(url=nmap.split(", ")[0])
			req.get_method = lambda : "OPTIONS"
			resp = opener.open(req)
			options = resp.info().getheaders('Allow')[0].replace(',','|')
			addtox("allow", options)
		except Exception:
			pass

		resp = None

	if getRobots:
		try:
			host = nmap.split(", ")[0].split(":")[1].replace("//",'')
			dat = opener.open("%s/robots.txt"%nmap.split(", ")[0])
			dat_content = dat.read()
			if dat.getcode() == 200 and "llow:" in dat_content: 
				if not os.path.exists("robots"): os.makedirs("robots")
				open("./robots/%s_robots.txt"%host,'w').write(dat_content)
				output.put("   [r] Pulled robots.txt:  ./robots/%s_%s_robots.txt  "%(host,nmap.split(", ")[3]))
				addtox("robots.txt", "y")

			dat = None
		except Exception:
			pass

	# eat cookie now....omnomnom
	if hasattr(data, 'info'):
		cookies = data.info().getheaders('Set-Cookie')
		if cookies and (len(cookies) > 0): 	
			try:
				os.mkdir("cookies")
			except:
				pass

			cout = ""
			for cookie in cookies:
				cout += cookie+'\n\n'

			open("./cookies/%s_%s.txt"%(nmap.split(", ")[0].split('/')[2].split(':')[0],nmap.split(", ")[3]),'w').write(cout)
			addtox("cookies", len(cookies))

	try:		
		server_type = ""
		html = data.read()
		addtox("endurl", data.geturl())
		addtox("returncode", "[%s]"%str(data.getcode()))
		for field in data.info().__str__().split("\r\n"):
			if field != "":
				fname = field.split(": ")[0]
				fval = re.sub('[\n\r]', '', field.split(": ")[1])
				fval = fval.replace(",",'')
				if "server" in fname.lower():
					server_type=fval.lower()

				addtox(fname.lower(), fval)

		addtox("info", (re.sub('[\n\r,]', '', data.info().__str__())))
	except: 
		html = str(data)

	if "urlopen error [Errno" in html:
		line = "%s%s"%(nmap,', '.join(x))
	else:
		addtox("title", ' : '.join(re.findall("""<title.*?>([^<]+)<\/title>""",html,re.I)))

		meta = re.findall("""<meta[^>^=]+content[\s]*=[\s]*['"]([^"^'^>]+)['"][^>^=]+name[\s]*=[\s]*['"]?(.*)['"]?""",html,re.I)
		meta += re.findall("""<meta[^>^=]+name[\s]*=[\s]*['"]?(.*)['"]?[^>^=]+content[\s]*=[\s]*['"]?([^"^'^>]+)['"]?""",html,re.I)
		m = ""
		for field in meta:
			if field != "":
				fname = field[0].strip('"')   
				fval = re.sub('[\n\r,]', '', field[1])
				m += "%s:%s, "%(fname,fval)
				addtox(fname.lower(), fval)

		addtox("meta", m.replace(",",'; '))

		# regexes based on the page content
		addtox("analytics_ID", ';'.join(re.findall("""["']UA-[0-9]{8}-[0-9]{1}["']""",html,re.I)))
		addtox("passwordfields", ';'.join(re.findall("""<input [^>]*?type=["']password["'][^>]*>""",html,re.I)))
		addtox("emailaddresses", ';'.join(list(set(re.findall("""[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}""",html,re.I)+(re.findall("""<[^>]+href=[^>]*mailto:([^\'\"\?>]+)[^>]*>""",html,re.I))))))

		if len(re.findall("""<!DOCTYPE html>""",html,re.I)) > 0:
			addtox("HTML5", "True")
		else:
			addtox("HTML5", "False")

	#looking for SSL data
	if any(s in nmap.split(", ")[7].lower() for s in ["https","ssl"]):
		ssl_data = ""
		for xmlfile in glob.glob("*.nessus")+glob.glob("*.xml"):
			try:
				if "<NessusClientData_v2>" in open(filename).read():
					for node in minidom.parse(filename).getElementsByTagName('ReportHost'): 
						for item in node.getElementsByTagName('ReportItem'):
							service = item.getAttribute('svc_name')
							plugin = item.getAttribute('pluginName')
							if (service == "www") and (plugin == "SSL Certificate Information"):
								#SSL stuff  ..  ;)
								pass
								#nmapout += ", ".join([ip,hostname,portnum,state,protocol,owner,service,sunrpc_info,version_info])+", \n"
								#count += 1

								if (nmap.split(", ")[1] in hostnames) or (match == True):
									#we're on the correct report item - placeholder here until i can get the format
									output.put("......Found SSL data for %s....."%nmap.split(', ')[1])
									#addtox("SSL_Tunnel-Weakest", weakest.strip())
									#addtox("SSL_Tunnel-Ciphers", ciphers.strip("; "))
									#addtox("SSL_Tunnel-CiphersRaw", c_data.replace("\n",";"))
									#ssl_data = script.getAttribute('output')

								break; break

				else:
					# nmap xml output
					dom = minidom.parse(xmlfile).getElementsByTagName('nmaprun')[0]
					for node in dom.getElementsByTagName('host'): 
						h = ""		
						for n in node.getElementsByTagName('hostname'):
							h += n.getAttribute('name')

						for n in node.getElementsByTagName('address'):
							h += n.getAttribute('addr')
			
						match = False
						for hostname in nmap.split(", ")[2].split('|'):
							if hostname in h:
								match == True
								break

						if (nmap.split(", ")[1] in h) or (match == True):
							for port in node.getElementsByTagName('port'):
								if port.getAttribute('portid') == nmap.split(", ")[3]: 
									for script in port.getElementsByTagName('script'):
										if script.getAttribute('id') == "ssl-enum-ciphers":
											ciphers = ""
											c_data = script.getAttribute('output')
											addtox("SSL_Tunnel-CiphersRaw", c_data.replace("\n",";"))
											c_data = c_data.split('NULL\n  ')
											for v in c_data[0:-1]:
												ciphers+= v.strip('\n').strip().split('\n')[0]+"; "

											addtox("SSL_Tunnel-Ciphers", ciphers.strip("; "))
											weakest = c_data[-1].strip('\n').strip().split('=')
											if len(weakest) > 1:
												weakest = weakest[1]
											else:
												weakest = weakest[0]

											addtox("SSL_Tunnel-Weakest", weakest.strip())

										if script.getAttribute('id') == "ssl-cert":
											ssl_data = script.getAttribute('output')

									break; break

				try:
					dom.unlink()
				except:
					pass

			except Exception, ex:
				output.put("\n\n  !! Unable to parse %s  !!\n\t\t Error: %s\n\n"%(filename,ex))

		if ssl_data != "":
			# write the cert to a file
			if not os.path.exists("ssl_certs"):
				os.mkdir("ssl_certs") 

			open("./ssl_certs/%s.cert"%(nmap.split(", ")[1]),'w').write(ssl_data)
			addtox("SSL_Cert-Raw", ssl_data)
			ssl_data = ssl_data.split('\n')
			addtox("SSL_Cert-Issuer", ssl_data[1].split(": ")[1])
			addtox("SSL_Cert-Subject", ssl_data[0].split(": ")[1])
			if "*" in ssl_data[0].split(": ")[1]:
				subject = ssl_data[0].split(": ")[1].split("*")[1]
			else:
				subject = ssl_data[0].split(": ")[1]

			if subject in nmap.split(', ')[0:3]: 
				addtox("SSL_Cert-Verified", "yes")

			addtox("SSL_Cert-KeyAlg", "%s%s"%(ssl_data[2].split(": ")[1],ssl_data[3].split(": ")[1]) )
			addtox("SSL_Cert-MD5", ssl_data[6].split(": ")[1].replace(" ",''))
			addtox("SSL_Cert-SHA-1", ssl_data[7].split(": ")[1].replace(" ",''))
			addtox("SSL_Cert-notbefore", ssl_data[4].split(": ")[1].strip())
			addtox("SSL_Cert-notafter", ssl_data[5].split(": ")[1].strip())
			try:
				notbefore = datetime.strptime(ssl_data[4].split(": ")[1].strip(" "), '%Y-%m-%d %H:%M:%S')
				notafter = datetime.strptime(ssl_data[5].split(": ")[1].strip(" "), '%Y-%m-%d %H:%M:%S')
				vdays = ( notafter - notbefore ).days
				if datetime.now() > notafter: 
					daysleft = "EXPIRED"
				else: 
					daysleft = ( notafter - datetime.now() ).days

			except ValueError:
				# some certificates have non-standard dates in these fields.  
				vdays = "unk"
				daysleft = "unk"

			addtox("SSL_Cert-ValidityPeriod", vdays)
			addtox("SSL_Cert-DaysLeft", daysleft)

	# check title, service, and server fields for matches in defpass file
	if defpass:
		defpwd = ""
		services_txt = ",".join(nmap.split(',')[6:]).lower()+",%s"%server_type
		for pdef in defpass:
			try:
				if not pdef.startswith("#"):
					if (pdef.split(',')[0].lower() in (services_txt) ): 
						defpwd += "%s;"%(':'.join(pdef.split(',')[0:5]))
			except Exception, ex:
				output.put(" -- Error parsing defpass.csv: %s --"%ex)

		if defpwd: 
			addtox("Default Password Suggestions",defpwd.strip(";"))

	try:
		xdata = str(','.join(x))
		nmap = str(nmap)
	except Exception, ex:
		output.put("\t\t!!  Error - "%ex)
		output.put(x)
		xdata = ""

	open('index_%s.html'%timestamp,'a').write("%s%s<br>"%(nmap,xdata))
	open("rawr_%s_serverinfo.csv"%timestamp,'a').write("\n%s"%(xdata))


def write_to_csv(ip, hostname, portnum, state, protocol, owner, service, sunrpc_info, version_info):
	global timestamp
	global flist

	x=[" "] * len(flist.split(","))

	if not os.path.exists("rawr_%s_serverinfo.csv"%timestamp):
		open("rawr_%s_serverinfo.csv"%timestamp,'w').write(flist)

	addtox("host_ip", ip)
	addtox("hostname", hostname)
	addtox("port", portnum)
	addtox("state", state)
	addtox("protocol", protocol)
	addtox("owner", owner)
	addtox("service", service)
	addtox("rpc_info", sunrpc_info)
	addtox("version", version_info)		

	try:
		open("rawr_%s_serverinfo.csv" % timestamp,'a').write("\n%s" % (str(','.join(x))))
	except Exception, ex:
		print "\t\t    [!] Unable to write .csv !\n\t\t Error: %s\n\n" % ex
		print x


def update(force):
	print banner
	global scriptpath
	global version
	global pjs_path

	os.chdir(scriptpath)

	url = 'https://bitbucket.org/al14s/rawr/downloads/ver.csv'
	print "  ++ Checking current versions...  >\n   %s\n"%url
	try:
		ver_data = urllib2.urlopen(url).read()
		script_ver = ver_data.split(",")[0].split(":")[0].replace('\n','')
		script_files = ver_data.split(",")[0].split(":")[1:]
		defpass_ver = ver_data.split(",")[1].replace('\n','')
		ip2c_ver = ver_data.split(",")[2].replace('\n','')
		pJS_ver = ver_data.split(",")[3].replace('\n','')
	except Exception, ex:
		print "  !! Failed:  %s\n"%ex
		sys.exit(1)

	# check for updated version of script
	if script_ver > version:
		choice = raw_input('\n  ** Update RAWR v%s to v%s? [Y/n]:'%(version,script_ver))
		if (choice.lower() in ("y","yes",'')):
			print "\n  ++ Updating  RAWR v%s >> v%s\n"%(version,script_ver)
			url ="https://bitbucket.org/al14s/rawr/downloads/rawr_"+script_ver+".tar"
			print "\tPulling - "+url
			try:
				data = urllib2.urlopen(url).read()
				open("rawr_"+script_ver+".tar",'w+b').write( urllib2.urlopen(url).read() )
				tarfile.open("rawr_"+script_ver+".tar").extractall('../')
				os.remove("rawr_"+script_ver+".tar")
			except Exception, ex:
				print "\n    !! Error pulling: "+url+"\n\t\t - "+str(ex)
				print "     Try pulling lastest version from https://bitbucket.org/al14s/rawr\n\n"
				sys.exit(1)

			print "\n     ++ Update successful.  Restarting script... ++  \n\n"
			time.sleep(3)
			python = sys.executable
			os.execl(python, python, * sys.argv)
		else:
			print "\n  ++ RAWR v%s found (current is %s) ++\n"%(version,script_ver)

	else:
		print "  ++ RAWR v%s found (current) ++\n"%version


	if ckinstall:
		# nmap
		if not (inpath("nmap") or inpath("nmap.exe")):
			print "  !! NMap not found in $PATH.  You'll need to install it to use RAWR.  \n"
		else:
			proc = subprocess.Popen(['nmap','-V'], stdout=subprocess.PIPE)
			ver = proc.stdout.read().split(' ')[2]
			main_ver = ver.split('.')[0]
			if int(main_ver) < 6: 
				print "  ** NMap %s found, but versions prior to 6.00 won't return all SSL data. **\n"%ver
			else:
				print "  ++ NMap %s found ++\n"%ver

		try:
			proc = subprocess.Popen([pjs_path,'-v'], stdout=subprocess.PIPE)
			pJS_curr = re.sub('[\n\r]', '', proc.stdout.read())
		except:
			pJS_curr = ""
	
		if force or (pJS_ver > pJS_curr) or not (inpath("phantomjs") or inpath("phantomjs.exe") or os.path.exists("phantomjs/bin/phantomjs") or os.path.exists("phantomjs/phantomjs.exe")):
			if not force:		
				if pJS_curr != "" and (pJS_ver > pJS_curr):
					txt = '\n  !! phantomJS %s found (current is %s) - do you want to update? [Y/n]: '%(pJS_curr,pJS_ver)
					choice = raw_input(txt)
				else:
					choice = raw_input('\n  !! phantomJS was not found - do you want to install it? [Y/n]: ')

				if not (choice.lower() in ("y","yes",'')): 
					print "\n  !! Exiting...\n\n"
					sys.exit(0)
			
			# phantomJS
			pre = "phantomjs-%s"%pJS_ver
			if  platform.system() in "CYGWIN|Windows": 
				fname = pre+"-windows.zip"
			elif platform.system().lower() in "darwin": 
				fname = pre+"-macosx.zip"
			elif sys.maxsize > 2**32: 
				fname = pre+"-linux-x86_64.tar.bz2"
			else: 
				fname = pre+"-linux-i686.tar.bz2"  # default is 32bit *nix

			url = "http://phantomjs.googlecode.com/files/%s"%(fname)
			print "\n  ++ Pulling/installing phantomJS >\n   %s"%url

			try:
				open(fname,'w+b').write( urllib2.urlopen(url).read() )

				if os.path.exists("phantomjs"):
					def onerror(func, path, exc_info):
						if not os.access(path, os.W_OK):
							os.chmod(path, stat.S_IWUSR)
							func(path)

					shutil.rmtree("phantomjs",onerror=onerror)

				if fname.endswith(".zip"):
					import zipfile
					zipfile.ZipFile(fname).extractall('.')
				else: 
					tarfile.open(fname).extractall('.')		
				
				os.rename(str(os.path.splitext(fname)[0].replace(".tar",'')), "phantomjs")
				os.remove(fname)

				if platform.system().lower() in "darwin": 
					os.chmod("phantomjs/bin/phantomjs",755)
					# Mac OS X: Prevent showing the icon on the dock and stealing screen focus.
					#   http://code.google.com/p/phantomjs/issues/detail?id=281
					f = open("phantomjs/bin/Info.plist",'w')
					f.write('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist SYSTEM "file://localhost/System/Library/DTDs/PropertyList.dtd"><plist version="0.9"><dict><key>CFBundleExecutable</key><string>phantomjs</string><key>CFBundleIdentifier</key><string>org.phantomjs</string><key>LSUIElement</key><string>1</string></dict></plist>')
					f.close()
					
				print "     ++ Success ++\n"
			except Exception, ex:
				print "  !! Failed:  %s\n"%ex

		else:
			print "  ++ phantomJS %s found (current supported version) ++\n"%pJS_curr


	defpass_curr = 0
	if os.path.exists("defpass.csv"):
		ofile = open("defpass.csv").readlines()
		for line in ofile:
			if line.startswith("#"):
				defpass_curr = line.split(' ')[1].replace('\n','')

	if not os.path.exists("defpass.csv") or force or (defpass_ver > defpass_curr):
		# defpass
		url = 'https://bitbucket.org/al14s/rawr/downloads/defpass.csv'
		print "  ++ Updating defpass.csv rev.%s >> rev.%s\n   %s"%(defpass_curr,defpass_ver,url)
		try:
			open("defpass_latest.csv",'w').write( urllib2.urlopen(url).read() )
			try: 
				os.remove("defpass.csv")
			except: 
				pass

			os.rename("defpass_latest.csv","defpass.csv")
			c = 0 
			for line in open("defpass.csv").read().split('\n'):
				c += 1

			print "     ++ Success - (Contains %s entries)  ++"%c
		except Exception, ex:
			print "     !! Failed:  %s\n"%ex
	else:
		print "     -- NOT updating defpass.csv - already at rev.%s"%defpass_ver

	ip2c_curr = 0
	if os.path.exists("IpToCountry.csv"):
		ofile = open("IpToCountry.csv").readlines()
		for line in ofile:
			if "# Software Version" in line:
				ip2c_curr = line.split(" ")[5].replace('\n','')
				break

	if not os.path.exists("IpToCountry.csv") or force or (ip2c_ver > ip2c_curr):
		# IpToCountry
		url = 'https://bitbucket.org/al14s/rawr/downloads/IpToCountry.csv.tar.gz'
		print "\n  ++ Updating IpToCountry.csv ver.%s >> ver.%s\n   %s"%(ip2c_curr,ip2c_ver,url)
		try:
			open("IpToCountry.csv.tar.gz",'w+b').write( urllib2.urlopen(url).read() )
			tarfile.open("IpToCountry.csv.tar.gz").extractall('.')
			os.remove("IpToCountry.csv.tar.gz")
			print "     ++ Success ++\n"
		except Exception, ex:
			print "     !! Failed:  %s\n"%ex
			sys.exit(1)
	else:
		print "\n     -- NOT updating IpToCountry.csv - already at ver.%s\n"%ip2c_ver

	print "  ++  Update Complete  ++\n\n"
	sys.exit()


def inpath(app):
	for path in os.environ["PATH"].split(os.pathsep):
		exe_file = os.path.join(path, app)
		if os.path.isfile(exe_file) and os.access(exe_file, os.X_OK):
			return exe_file


def writelog(msg):
	print msg
	open("%s/rawr_%s.log"%(logdir,timestamp),'a').write(msg+"\n")


def error_w_banner(msg):
	print "%s\n  -= %s =-\n"%(banner,msg)
	sys.exit(1)



# Start
##################################
scriptpath = os.path.dirname(os.path.realpath(__file__))	
timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

if inpath("phantomjs"):
	pjs_path = "phantomjs"

elif os.path.exists("%s/phantomjs/bin/phantomjs"%scriptpath):
	pjs_path = "%s/phantomjs/bin/phantomjs"%scriptpath

elif platform.system() in "CYGWIN|Windows" and inpath("phantomjs.exe"):
	pjs_path = "phantomjs.exe"

elif platform.system() in "CYGWIN|Windows" and (os.path.exists("%s/phantomjs/phantomjs.exe"%scriptpath)):
	pjs_path = "%s/phantomjs/phantomjs.exe"%scriptpath

else:
	pjs_path = ""


try: 
	opts, args = getopt.getopt(sys.argv[1:], "abd:ef:hi:n:op:rs:t:quUyz", ["help","compress-logs","logo=","title=","downgrade","sslv","check-install","force-install","quiet"])

except getopt.GetoptError, err: 
	print "%s\n%s\n\n\t!!   %s   !!\n\n"%(banner,usage,str(err))
	exit(2)

for o, a in opts:
	if o == ("-a"):
		allinfo = True

	elif o == ("-b"):
		bing_dns = True

	elif o == ("-d"):
		logdir = os.path.realpath(a)

	elif o == ("--downgrade"):
		ver_dg = True

	elif o == ("-e"):
		defpass = False

	elif o == ("-f"):
		if not os.path.exists(os.path.abspath(a)): 
			error_w_banner("Unable to locate [%s]."%os.path.abspath(a))

		if os.path.isdir(a):
			for f in glob.glob("%s/*.xml"%a):
				files.append(os.path.realpath(f))

			if not files:
				error_w_banner("No .xml files in [%s]."%a)
		else: 
			xmlfile = True
			files = [os.path.realpath(a)]

	elif o in ("-h", "--help"):
		print banner+usage+summary+examples
		sys.exit()

	elif o == ("-i"):
		if os.path.exists(a): 
			nmap_il = os.path.realpath(a)
		else:
			error_w_banner("Unable to locate data source [%s]."%a)

	elif o == ("--logo"):
		if os.path.exists(os.path.abspath(a)):
			from PIL import Image
			i = Image.open(os.path.abspath(a)).size
			if i[0] > 400 or i[1] > 60:
				print "[ warning ]  The specified logo may not show up correctly.\n\tA size no larger than 400x60 is recommended.\n"

			logo_file = os.path.realpath(a)

		else:
			error_w_banner("Unable to locate logo file [%s]."%a)

	elif o == ("-n"):
		nmaprng = a

	elif o == ("-o"):
		getoptions = True

	elif o == ("-p"):
		if a.lower() == "fuzzdb":
			ports = fuzzdb

		elif a.lower() == "all":
			ports = "1-65535"

		else:
			ports = a

	elif o == ("-u"):
		update(False)

	elif o == ("-U"):
		update(True)

	elif o == ("--check-install"):
		ckinstall=True
		update(False)

	elif o == ("--force-install"):
		ckinstall = True
		update(True)

	elif o == ("-s"):
		sourceport = a

	elif o == ("-t"):
		try:
			if 6 > int(a) > 0:
				nmapspeed = a
			else:
				raise()
		except:
			error_w_banner("Scan Timing (-t) must be numeric and 1-5")

	elif o == ("--title"):
		if len(o) > 60:
			writelog("The title specified might not show up properly.")

		report_title = a

	elif o == ("--sslv"):
		sslopt = ",ssl-enum-ciphers"

	elif o in ("-q","--quiet"):
		quiet = True

	elif o == ("-r"):
		getRobots = True

	elif o == ("-y"): 
		import random;i="Random,Ragged,Rabid,Rare,Radical,Rational,Risky,Remote,Rowdy,Rough:Act,Audit,Arming,Affront,Arc,Attack,Apex,Assault:Wily,Weird,Wonky,Wild,Wascawy,Wimpy,Winged,Willing,Working,Warring:Ravioli,Rats,Rabbits,Rhinos,Robots,Rigatoni".split(':'); e="%s %s of %s %s"%(random.choice(i[0].split(',')),random.choice(i[1].split(',')),random.choice(i[2].split(',')),random.choice(i[3].split(','))); e=(" "*((18-len(e)/2)))+e+(" "*((18-len(e)/2))); print banner.replace("  Rapid Assessment of Web Resources ",e[0:36]); sys.exit()

	elif o in ("-z","--compress-logs"):
		compress_logs = True

	else:
		print "\n  !! Unhandled option:  %s %s  !!\n" % (o,a)
		sys.exit(1)


if not quiet: 
	print banner


# Do some pre-run checks
if len(sys.argv) < 2 or (len(sys.argv) < 3 and quiet):
	print usage
	sys.exit(1)
elif not (nmaprng != "" or nmap_il != "" or files): 
	print "\n  !! No input specified / found in supplied path. !!\n"
	sys.exit(1)
elif (nmaprng != "" and nmap_il != ""):
	print "\n  !! Can't use -i and -n at the same time.  !!\n\n"
	sys.exit(1)


# build our global opener
socket.setdefaulttimeout(timeout)
if ver_dg:   #downgrade to HTTP 1.0
	httplib.HTTPConnection._http_vsn = 10
	httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'

opener = urllib2.build_opener(urllib2.HTTPSHandler())
opener.addheaders = [('User-agent', useragent)]


if pjs_path == "":
	print "  !! phantomJS not found in $PATH or in RAWR folder.  \n\n\tTry running 'rawr.py --check-install'\n\n  !! Exiting... !!\n\n"
	sys.exit(1)


# Create the log directory and start logging.
if not logdir: 
	logdir = os.path.realpath("log_%s_rawr"%timestamp)
if not os.path.exists(logdir): 
	os.makedirs(logdir)
	newdir = True

os.chdir(logdir)

msg = "\nStarted RAWR : %s\n     cmdline : %s\n\n"%(timestamp," ".join(sys.argv))
open("%s/rawr_%s.log"%(logdir,timestamp),'a').write(msg)
writelog("\n  -= Log Folder created : %s =-\n"%logdir)


if defpass:
	if os.path.exists("%s/defpass.csv"%scriptpath): 
		writelog("\n   -= Located defpass.csv =-\n")
		# load defpass into memory - if it gets too big, this will change
		defpass = [line.strip() for line in open("%s/defpass.csv"%scriptpath)]
	else:
		writelog("\n   -= Unable to locate defpass.csv. =-\n")
		choice = raw_input("\tContinue without default password info? [Y|n] ").lower()
		defpass = False
		if (not choice in "yes") and choice != "": 
			sys.exit(2)


# run NMap
if nmap_il != "" or nmaprng != "":
	if nmap_il != "" or (re.match('^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}(:[0-9]{1,5})?(\/.*)?$',nmaprng) or (re.match('^((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}){0,}|\*)\.(((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*)\.){2}((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*|([0]{1}\/(8|9|[1-2]{1}[0-9]{1}|30|31|32){1})){1}$',nmaprng) and not re.match('([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))',nmaprng) and not re.match('([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))',nmaprng))):
		# ^^ check for valid nmap input (can use hostnames, subnets (ex. 192.168.0.0/24), stars (ex. 192.168.*.*), and split ranges (ex. 192.168.1.1-10,14))
		if not (inpath("nmap") or inpath("nmap.exe")):
			writelog("  !! NMap not found in $PATH.  Exiting... !!\n\n")
			sys.exit(1)

		writelog("  -= Beginning NMap Scan =-")

		cmd = ["nmap","-Pn"]

		if sourceport != "":
			cmd += "-g",sourceport

		cmd += "-p",ports,"-T%s"%nmapspeed,"-vv","-sV","--script=ssl-cert"+sslopt,"-oA","rawr_"+timestamp,"--open"

		if nmap_il != "": 
			cmd += "-iL",nmap_il
		else:
			cmd.append(nmaprng)

		writelog('  Running > '+" ".join(cmd))

		try:
			with open("%s/rawr_%s.log"%(logdir,timestamp),'ab') as log_pipe:
				ret = subprocess.call(cmd, stdout=None, stderr=log_pipe)
		except KeyboardInterrupt: 
			writelog("\n\n **  Scanning Halted (ctrl+C).  Exiting!   ** \n\n")
			sys.exit(2)
		except Exception, ex: 
			writelog("\n\n **  Error in scan - %s   ** \n\n"%ex)
			sys.exit(2)

		if ret != 0:
			writelog("\n\n")
			sys.exit(1)

		files = ["rawr_%s.xml"%timestamp]

	else:
		writelog("\n  !! Specified address range is invalid. !!\n")
		sys.exit(1)

elif newdir:
	#move the user-specified xml file(s) into the new log directory
	old_files = files
	files = ""
	for filename in old_files:
		shutil.copyfile(filename,"./"+os.path.basename(filename))
		files += filename+","

	files = files.strip(",").split(",")
		

if not newdir and not (glob.glob("*.png") or glob.glob("images/*.png")): 
	writelog("\n ** No thumbnails found in [%s/]\n\t\t or in [.%s/images/]. **\n"%(os.getcwd(),os.getcwd()))
	writelog("\tWill take website screenshots during the enumeration. ")
else: 
	if not os.path.exists("images"):
		os.mkdir("images")

	for filename in glob.glob("*.png"):
		newname = filename.replace(":","_")
		os.rename(filename, "./images/%s"%(newname))

q = Queue.Queue()

for filename in files:
	writelog("[>] Parsing\t: %s  for web hosts..."%filename)
	try:
		dom = minidom.parse(filename)

		if len(dom.getElementsByTagName('NexposeReport')) > 0:
			############
			# Nexpose
			############
			for node in dom.getElementsbyTagName('node'):
				ip = node.getElementsbyTagName('address').firstChild.nodeValue
				hostname = node.getElementsbyTagName('name').firstChild.nodeValue

				portnum = ""

				state = "open"

				protocol = ""

				owner = ""

				service = ""

				sunrpc_info = ""

				version_info = ""

				if web:
						q.put(", ".join([ip,hostname,portnum,state,protocol,owner,service,sunrpc_info,version_info]))

				elif allinfo:
					write_to_csv(ip,hostname,portnum,state,protocol,owner,service,sunrpc_info,version_info)

		if len(dom.getElementsByTagName('ASSET_DATA_REPORT')) > 0:
			############
			# Qualys
			############
			for host in dom.getElementsByTagName('HOST'):
				hostname = ""
				ip = host.getElementsByTagName('IP')[0].firstChild.nodeValue
				if len(host.getElementsByTagName('DNS')) > 0:
					hostname = host.getElementsByTagName('DNS')[0].firstChild.nodeValue

				for name in host.getElementsByTagName('NETBIOS'):
							if not name.firstChild.nodeValue.lower() in hostname.lower():
								hostname += "|" + name.firstChild.nodeValue

				for vuln in host.getElementsByTagName('VULN_INFO'):
					if vuln.getElementsByTagName('QID')[0].firstChild.nodeValue == "86000":
						for name in vuln.getElementsByTagName('FQDN'):
							if not name.firstChild.nodeValue.lower() in hostname.lower():
								hostname += "|" + name.firstChild.nodeValue

						portnum = vuln.getElementsByTagName('PORT')[0].firstChild.nodeValue
						state = "open"
						protocol = vuln.getElementsByTagName('PROTOCOL')[0].firstChild.nodeValue
						owner = ""
						service = vuln.getElementsByTagName('SERVICE')[0].firstChild.nodeValue
						sunrpc_info = ""
						version_info = vuln.getElementsByTagName('RESULT')[0].firstChild.nodeValue
						version_info = version_info.split("\t")[2]

						q.put(", ".join([ip,hostname,portnum,state,protocol,owner,service,sunrpc_info,version_info]))

		elif len(dom.getElementsByTagName('NessusClientData_v2')) > 0:
			############
			# Nessus
			############
			for node in dom.getElementsByTagName('ReportHost'): 
				for item in node.getElementsByTagName('ReportItem'):
					plugin = item.getAttribute('pluginName')
	 				if plugin == "Service Detection":
						hostname = node.getAttribute('name')
						service = item.getAttribute('svc_name')
						ip = ""
						state = ""
						owner = ""
						sunrpc_info = ""
						version_info = ""
						systype = ""

						for subele in node.getElementsByTagName('tag'):
							name = subele.getAttribute('name')
							val = subele.firstChild.nodeValue
							if name == "host-ip":
								ip = val
							elif name == "operating-system": 
								version_info = val
							elif name == "system-type": 
								systype = val
							elif name == "netbios-name": 
								hostname += ("|" + val)

						version_info += " (%s)"%systype
			
						protocol = item.getAttribute('protocol')
						portnum = item.getAttribute('port')
						plugin_output = item.getElementsByTagName("plugin_output")[0].firstChild.nodeValue
			
						service = "http"
						if any(s in plugin_output.lower() for s in ["ssl","tls"]):
							service += "s"

						if (service == "www"):
							q.put(", ".join([ip,hostname,portnum,state,protocol,owner,service,sunrpc_info,version_info]))

						elif allinfo:
							write_to_csv(ip,hostname,portnum,state,protocol,owner,service,sunrpc_info,version_info)

		elif len(dom.getElementsByTagName('nmaprun')) > 0:
			############
			# NMap
			############
			for node in dom.getElementsByTagName('host'): 
				if len(node.getElementsByTagName('ports')) > 0:
					for port in node.getElementsByTagName('ports')[0].getElementsByTagName('port'):
						if port.getElementsByTagName('state')[0].getAttribute('state') == "open": 
							ip = node.getElementsByTagName('address')[0].getAttribute('addr')
							hostname = []
							for hn in node.getElementsByTagName('hostname'):
								if not hn.getAttribute('name') in hostname:
									hostname.append(hn.getAttribute('name'))

							hostname = '|'.join(hostname)
							portnum = port.getAttribute('portid')
							protocol = port.getAttribute('protocol')
							state = port.getElementsByTagName('state')[0].getAttribute('state')
							owner = port.getElementsByTagName('owner')
							if len(owner) > 0: 
								owner = owner.getAttribute('name')
							else: 
								owner = " "

							# Enumerate service information
							service = "unknown"
							sunrpc_info = ""
							version_info = ""
							ele_service = port.getElementsByTagName('service')

							if len(ele_service) > 0: 
								ele_service = ele_service[0]
								service_tunnel = ele_service.getAttribute('tunnel')
								service = ele_service.getAttribute('name')
								if service_tunnel: 
									service = "%s|%s"%(ele_service.getAttribute('tunnel'),service)

								version_info = ele_service.getAttribute('product')
								if version_info != "": 
									version_info += " %s" % ele_service.getAttribute('version')

								ostype = ele_service.getAttribute('ostype')
								if ostype != "": 
									devtype = ele_service.getAttribute('devicetype')	
									if devtype != "": 
										version_info += " [%s - %s]"%(ostype,devtype)
									else: 
										version_info += " [%s]"%ostype

									xtra = ele_service.getAttribute('extrainfo')
									if xtra != "": 
										version_info += " (%s)" % xtra

							if any(s in service.lower() for s in ["ssl","http","tls"]):	
								q.put(", ".join([ip,hostname,portnum,state,protocol,owner,service,sunrpc_info,version_info]))	

							elif allinfo:
								write_to_csv(ip,hostname,portnum,state,protocol,owner,service,sunrpc_info,version_info)

		else:
			writelog("    [!] Unrecognized file format.  [ %s ]" % filename )
			continue

	except Exception, ex:
		writelog("\n\n    [!] Unable to parse %s !\n\t\t Error: %s\n\n" % ( filename, ex ))

	writelog("    [>] Found [ %s ] web hosts in %s..." % ( q.qsize(), filename ))

	try:
		dom.unlink()
	except:
		pass

	dom = None

if q.qsize() > 0:
	# create the folder for html resource files
	if not os.path.exists("./html_res"): 
		os.makedirs("./html_res")
	shutil.copy("%s/jquery.js"%scriptpath,"./html_res/jquery.js")
	shutil.copy("%s/report_template.html"%scriptpath,'index_%s.html'%timestamp)

	# make the link to NMap XML in our HTML report
	if len(files) == 1:
		if xmlfile == True:
			fname = os.path.basename(files[0])
		else:
			fname = "rawr_%s.xml"%timestamp

		filedat = open('index_%s.html' % timestamp).read()
		filedat = filedat.replace( '<!-- REPLACEWITHLINK -->', fname )
		filedat = filedat.replace( '<!-- REPLACEWITHDATE -->', datetime.now().strftime("%b %d, %Y") )
		filedat = filedat.replace( '<!-- REPLACEWITHTITLE -->', report_title )
		if nmap_il != "":
			report_range = nmap_il
			
		elif nmaprng != "":
			report_range = nmaprng
			
		else:
			if len(files) > 1:
				report_range = "%s files" % len(files)

			else:
				report_range = str(", ".join(files)[:40])

		
		filedat = filedat.replace( '<!-- REPLACEWITHRANGE -->', report_range )
		if logo_file != "":
			shutil.copy(logo_file, "./html_res/")
			filedat = filedat.replace( '<!-- REPLACEWITHLOGO -->', ( '\n<img id="logo" src="./html_res/%s" />\n' % os.path.basename(logo_file) ) )

		open('index_%s.html' % timestamp,'w').write( filedat )

	# for now - we're taking the NMap xml output as trustworthy
	for xmlfile in glob.glob("rawr_*.xml"):
		if os.path.exists("%s/nmap.xsl"%scriptpath) and not os.path.exists("./nmap.xsl"): 
			shutil.copy("%s/nmap.xsl"%scriptpath,"./html_res/nmap.xsl")

			fileloc = re.findall(r'.*href="(.*)" type=.*', open(xmlfile).read())[0]
			filedat = open(xmlfile).read().replace(fileloc,'html_res/nmap.xsl')
			open(xmlfile,'w').write(filedat)

			writelog("\n  Copied nmap.xsl to %s\n\tand updated link in xml files.\n\n"%(logdir))
		else: 
			writelog("\n  Unable to locate nmap.xsl.\n\n")

	if not os.path.exists("rawr_%s_serverinfo.csv"%timestamp):
		open("rawr_%s_serverinfo.csv"%timestamp,'w').write(flist)

	writelog("\n   -= Getting info from server(s) =-\n")

	# solves console output issues inherent to multithreading
	output = Queue.Queue()
	o = out_thread(output)
	o.daemon = True
	o.start()

	# create our main worker pool
	threads=[]
	for i in range(nthreads):
		t = sithread()
		threads.append(t)
		t.daemon = True
		t.start()

	try:
		while q.qsize() > 0:
			time.sleep(0.5)
			q.join()

	except KeyboardInterrupt:
		output.put("\n\n ******  Ctrl+C recieved - Stopping all threads.  ****** \n")

	output.put("\n\n   ** Finished.  Stopping Threads. **\n")
	for t in threads: 
		t.terminate = True

	output.join()
	output = None
	t = None
	o = None
	q = None
	
	# finish the html for our report
	open('index_%s.html'%timestamp,'a').write("</div></body></html>")

	# sort the csv on the specified column
	try: 
		i = flist.lower().split(", ").index(csv_sort_col)
		data_list = [line.strip() for line in open("rawr_%s_serverinfo.csv"%timestamp)]
		headers = data_list[0]
		data_list = data_list[1:]
		# format IP adresses so we can sort them effectively
		if re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", line.split(",")[i]): 
			key = "%3s%3s%3s%3s" % tuple(line.split(",")[i].split('.'))

		else: 
			key = line.split(",")[i]

		data_list.sort(key= lambda line: (key), reverse=False)
		open("rawr_%s_serverinfo.csv"%timestamp,'w').write(headers+"\n"+"\n".join(data_list))
	except:
		writelog("\n  --  '%s' was not found in the column list.  Skipping the CSV sort function.  --"%csv_sort_col)

	
	writelog("\n   ++ Report created in [%s/].  ++\n"%os.getcwd())
	if compress_logs:
		writelog("[>] Compressing logfile...\n")
		logdir = os.path.basename(os.getcwd())
		os.chdir("../")
		try:
			if  platform.system() in "CYGWIN|Windows":
				shutil.make_archive(logdir, "zip", logdir)
				logdir_c = logdir+".zip"
			else:
				tfile = tarfile.open(logdir+".tar", "w:gz")
				tfile.add(logdir)
				tfile.close()
				logdir_c = logdir+".tar"

			print "   ++ Created  %s ++\n"%(logdir_c)
			if os.path.exists(logdir) and os.path.exists(logdir_c):
				shutil.rmtree(logdir)

		except Exception, ex:
			print "   !! Failed - %s\n"%ex

else:
	writelog("\n   !! No data returned. !! \n\n")

