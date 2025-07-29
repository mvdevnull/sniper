#!/usr/bin/python3
#Script - sniper.py 
#Description - script used for DISCOVERY, various targeted nessus scans and Reports.
#Author - chrisdhebert@gmail.com
#Version - 2.2021-02-25

import psycopg2
import sys
import os
import re

dbpass = os.popen("cat /usr/share/metasploit-framework/config/database.yml | grep -m1 password | cut -d \":\" -f 2 | awk '{ gsub (\" \", \"\", $0); print}'").read()
constring = "dbname='msf' user='msf' host='localhost' port='5432' password='"+str(dbpass)+"'"
constring = constring.replace('\n', '')

#CONNECT TO PostgreSQL DB
try:
    conn = psycopg2.connect(constring)
except:
    print ("Error: Unable to connect to the database")

#PREPARE for SQL commands
cur = conn.cursor()
num_args = len(sys.argv)

###############################################
#Nessus PluginID Report Function
def nss_report(nss,desc,vuln):
        nss2 = "NSS-" + str(nss)

        cur.execute("""Select DISTINCT H.address, H.name, S.name, S.port, H.os_name from hosts H, vulns V, services S
        WHERE V.id in
        (Select vuln_id from vulns_refs where ref_id = (Select id from refs where name = '%s'))
        AND V.host_id = H.id AND S.id = V.service_id;
        """ %\
        (nss2))
        rows = cur.fetchall()
        if rows:
                print(desc,"---- Nessus PluginID=", nss, "(Old DB VulnID=", vuln, ")")
        else:
                pass
        for row in rows:
                print("\t", row[0], "\t", row[1], "\t", row[4]," (",row[2],"/",row[3],")")


###############################################
#SNIPER-DB-Cleaning
def db_update(cur):

	print("==========DB Updating Hosts=============")

	#SNIPER-SERVICE-Cleaning (Filtered SERVICES from initial discovery)"
	LIVE = cur.execute("""SELECT DISTINCT H.address from hosts H, services S where S.state in ('open','closed') and S.host_id = H.id """)
	LIVErows = cur.fetchall()
	SAVE = cur.execute("""SELECT DISTINCT H.address from hosts H where H.comments <> ''""")
	SAVErows = cur.fetchall()
	ALL = cur.execute("""SELECT DISTINCT H2.address from hosts H2""")
	ALLrows = cur.fetchall()
	DEADrows = list(set(ALLrows) - set(LIVErows) - set(SAVErows))
	#print("These proposed to delete", DEADrows)
	for DEADrow in DEADrows:
		cur.execute("""DELETE FROM hosts WHERE address = '%s' """ %\
		(DEADrow))
		conn.commit()
	#Cleaning Closed SERVICES (but server still up) 
	cur.execute("""DELETE FROM services S WHERE S.state in ('closed','filtered') """)
	conn.commit()
	#Marking alive hosts
	cur.execute("""UPDATE hosts SET comments = 'DISCOVERY-Updated-by-sniper.py' """)
	#At this point, we have all known hosts in the DB
	
	##################################################################################

	#OS UPDATES
	
	#OS-SUN
	#Sun via ssh
	cur.execute("""UPDATE hosts SET os_name = 'Sun', comments = 'OS-Updated-by-sniper.py'\
	where id in (SELECT host_id from services where name = 'ssh' and info like ('%Sun%')) and os_name = 'Unknown' """)

        #Cisco via any service
	cur.execute("""UPDATE hosts SET os_name = 'Cisco', comments = 'OS-Updated-by-sniper.py'\
	where id in (SELECT host_id from services where info like ('%isco%')) and os_name = 'Unknown' """)

        #Ubuntu via ssh
	cur.execute("""UPDATE hosts SET os_name = 'Linux', os_flavor = 'Ubuntu', comments = 'OS-Updated-by-sniper.py'\
	where id in (SELECT host_id from services where name = 'ssh' and info like ('%buntu%')) and os_name = 'Unknown' """)

        #CentOS via http
	cur.execute("""UPDATE hosts SET os_name = 'Linux', os_flavor = 'CentOS', comments = 'OS-Updated-by-sniper.py'\
	where id in (SELECT host_id from services where name = 'http' and info like ('%CentOS%')) """)

	#Debian via http
	cur.execute("""UPDATE hosts SET os_name = 'Linux', os_flavor = 'Debian', comments = 'OS-Updated-by-sniper.py'\
	where id in (SELECT host_id from services where name = 'http' and info like ('%Debian%')) """)
	
	#Linux via telnet
	cur.execute("""UPDATE hosts SET os_name = 'Linux', comments = 'OS-Updated-by-sniper.py'\
	where id in (SELECT host_id from services where port = 23 and info like ('%Linux%')) and os_name = 'Unknown' """)
        #BSD via telnet 
	cur.execute("""UPDATE hosts SET os_name = 'BSD', comments = 'OS-Updated-by-sniper.py'\
	where id in (SELECT host_id from services where port = 23 and info like ('%BSD%')) and os_name = 'Unknown' """)

        #OS-MS via any service
	cur.execute("""UPDATE hosts SET os_name = 'Microsoft Windows', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where (info like ('%icrosof%') or info like ('%indow%'))) and os_name = 'Unknown' """)
        #OS-MS via 445  -- (check logic of this one notice the () which means it got at least something back from 445
	cur.execute("""UPDATE hosts SET os_name = 'Microsoft Windows', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where (port = 445 and info <> '' )) and os_name = 'Unknown' """)

	#OS-ESX via SERVICES"
	cur.execute("""UPDATE hosts SET os_name = 'ESX', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name = 'http' and info like ('%ESX%')) and os_name ='Unknown' """)
	cur.execute("""UPDATE hosts SET os_name = 'ESX', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name = 'vmware-auth' and info like ('%VMware%')) """)

	#OS-F5-BIGIP via www
	cur.execute("""UPDATE hosts SET os_name = 'F5-BIGIP', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name in ('http', 'www') and info like ('%BIG-IP%')) """)

	#OS-ONTAP-NETAPP
	cur.execute("""UPDATE hosts SET os_name = 'NETAPP', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name in ('http', 'www') and info like ('%ONTAP%')) """) 

	#OS-CITRIX
	cur.execute("""UPDATE hosts SET os_name = 'CITRIX', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name in ('http', 'www', 'https') and info like ('%CITRIX%')) """) 
	cur.execute("""UPDATE hosts SET os_name = 'CITRIX', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name in ('ssl/http', 'http', 'www', 'https') and info like ('Citrix%')) """)

	#OS-Dell-Remote-Access(DRAC)
	cur.execute("""UPDATE hosts SET os_name = 'DELL', os_flavor = 'DRAC6', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name in ('http', 'www') and info like ('%iDRAC6%')) """) 

	#OS-APC UPS OS
	cur.execute("""UPDATE hosts SET os_name = 'APC OS', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name in ('http', 'ssh', 'www', 'ftp') and info like ('%APC%UPS%')) """)
	cur.execute("""UPDATE hosts SET os_name = 'APC OS', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where port in (80,21,22) and info like ('%APC%UPS%')) """)
	
	#OS-Wind River VxWorks
	#print "==========Phase 1.1.4 OS Updating (Wind River VxWorks via VxWorks SERVICES)"
	cur.execute("""UPDATE hosts SET os_name = 'Wind River VxWorks', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name = 'telnet' and info like ('%VxWor%')) and os_name ='Unknown' """)

	#OS-SUN-ILO
	#print "==========Phase 1.1.5 OS Updating (SUN ILO via Sun-ILOM SERVICES)"
	cur.execute("""UPDATE hosts SET os_name = 'SUN ILO', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name = 'http' and info like ('%Sun-ILOM%')) and os_name ='Unknown' """)

	#OS-HP Jet Direct
	#print "==========Phase 1.1.6 OS Updating (HP Printer (Jet Direct) via snmp SERVICES)"
	cur.execute("""UPDATE hosts SET os_name = 'HP Printer - Jet Direct', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name = 'snmp' and info like ('%JETDIRECT%')) and os_name ='Unknown' """) 
	cur.execute("""UPDATE hosts SET os_name = 'HP Printer - Jet Direct', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where name = 'http' and info like ('%JetDirect%')) and os_name ='Unknown' """)

        #OS-HP LaserJet via SERVICES
	cur.execute("""UPDATE hosts SET os_name = 'HP LaserJet', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where info like ('%LaserJet%')) and os_name ='Unknown' """)
	
        #OS-Axis Cameras ftp SERVICE
	cur.execute("""UPDATE hosts SET os_name = 'Axis Network Camera', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where port = 21 and info like ('%xis%amera%')) and os_name ='Unknown' """)
	cur.execute("""UPDATE hosts SET os_name = 'Axis Network Camera', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where port = 21 and info like ('%XIS%amera%')) and os_name ='Unknown' """)
        #OS-Avocent KVM via SERVICE
	cur.execute("""UPDATE hosts SET os_name = 'Avocent KVM', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where port = 443 and info like ('%vocent%KVM%')) and os_name ='Unknown' """)
        #OS-iDRAC via SERVICE
	cur.execute("""UPDATE hosts SET os_name = 'DELL iDRAC', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where info like ('%iDRAC%')) and os_name ='Unknown' """)
        #OS-TRENnet webcam via SERVICE
	cur.execute("""UPDATE hosts SET os_name = 'TRENDnet webcam', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where info like ('TRENDnet%webcam%')) and os_name ='Unknown' """)
        #OS-HP iLO via SERVICE
	cur.execute("""UPDATE hosts SET os_name = 'HP iLO', comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where info like ('%P Integrated Lights-Ou HP Integrated Lights-Ou%')) and os_name ='Unknown' """)
        #OS-CISCO VOIP via SERVICE"
	cur.execute("""UPDATE hosts SET os_name = 'CISCO', os_flavor = 'VOIP',comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where info like ('%andberg%VoIP%')) and os_name ='Unknown' """)
        #OS-POLYCOM VOIP via SERVICE"
	cur.execute("""UPDATE hosts SET os_name = 'POLYCOM', os_flavor = 'VOIP',comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where info like ('%olycom%VoIP%')) and os_name ='Unknown' """)
	#OS-NETGEAR Prosafe via SERVICE"
	cur.execute("""UPDATE hosts SET os_name = 'Netgear', os_flavor = 'Prosafe',comments = 'OS-Updated-by-sniper.py'
	where id in (SELECT host_id from services where info like ('%Netgear%ProSafe%')) and os_name ='Unknown' """)
	
	#LOGIC BUG - if we do this too early (before we get top200 and/or -sV) we get mistakes!!
	#If we do this, we should do it later on when top200 is confirmed to be already done
        #print Likely UNIX (EXCEPT (like UNION here ecludes the 445 windows and must be unknown os)
        #cur.execute("""UPDATE hosts set os_name = 'UNIX', comments = 'OS-Updated-by-sniper.py' where id in 
        #((select host_id from services where port in (22) ) EXCEPT SELECT DISTINCT id from hosts where id in 
        #(select host_id from services where port in (445) )) and os_name in ('Unknown') """)
	
	############################################################
	#OS_FLAVOR UPDATES
	#OS_FLAVOR-SLACKWARE (via hosts.info)
	cur.execute("""UPDATE hosts SET os_flavor = 'Slackware'
	where info like ('%lackware%') and os_flavor = '' """)
	cur.execute("""UPDATE hosts SET os_name = 'Linux', comments = 'OS-Updated-by-sniper.py'
	where os_flavor = 'Slackware'""")

	#OS_FLAVOR-WIN2k (via host.info)
	cur.execute("""UPDATE hosts SET os_flavor = '2000'
	where info like ('%Microsoft Windows 2000%') and os_flavor = '' """)
	cur.execute("""UPDATE hosts SET os_name = 'Microsoft Windows', comments = 'OS-Updated-by-sniper.py'
	where os_flavor = '2000'""")

	#OS_FLAVOR-WIN2k3 (via host.info)
	cur.execute("""UPDATE hosts SET os_flavor = '2003'
	where info like ('%Microsoft Windows Server 2003%') """)

	#OS_FLAVOR-UBUNTU (via os_name )"
	cur.execute("""UPDATE hosts SET os_flavor = 'Ubuntu', comments = 'OS-Updated-by-sniper.py'
	where os_name like ('%buntu%') and os_flavor = '' """)
	cur.execute("""UPDATE hosts SET os_name = 'Linux', comments = 'OS-Updated-by-sniper.py'
	where os_flavor = 'Ubuntu'""")

	#OS_FLAVOR-Debian (via os_name)
	cur.execute("""UPDATE hosts SET os_flavor = 'Debian', comments = 'OS-Updated-by-sniper.py'
	where os_name like ('%Debian%') and os_flavor = '' """)
	cur.execute("""UPDATE hosts SET os_name = 'Linux', comments = 'OS-Updated-by-sniper.py'
	where os_flavor = 'Debian'""")

	#OS_FLAVOR-CentOS (via os_name)
	cur.execute("""UPDATE hosts SET os_flavor = 'CentOS', comments = 'OS-Updated-by-sniper.py'
	where os_name like ('%CentOS%') and os_flavor = '' """)
	cur.execute("""UPDATE hosts SET os_name = 'Linux', comments = 'OS-Updated-by-sniper.py'
	where os_flavor = 'CentOS'""")

	#OS_FLAVOR-Fedora (via os_name)
	cur.execute("""UPDATE hosts SET os_flavor = 'Fedora', comments = 'OS-Updated-by-sniper.py'
	where os_name like ('%Fedora%') and os_flavor = '' """)
	cur.execute("""UPDATE hosts SET os_name = 'Linux', comments = 'OS-Updated-by-sniper.py'
	where os_flavor = 'Fedora'""")

        ####################################################
	#OS Service_PACK UPDATES
	
	#OS_SP-Win-SP1-6 (via host.info)
	cur.execute("""UPDATE hosts SET os_sp = 'SP1'
	where info like ('%Microsoft Windows%Service Pack 1%') """)
	cur.execute("""UPDATE hosts SET os_sp = 'SP2'
	where info like ('%Microsoft Windows%Service Pack 2%') """)
	cur.execute("""UPDATE hosts SET os_sp = 'SP3'
	where info like ('%Microsoft Windows%Service Pack 3%') """)
	cur.execute("""UPDATE hosts SET os_sp = 'SP4'
	where info like ('%Microsoft Windows%Service Pack 4%') """)
	cur.execute("""UPDATE hosts SET os_sp = 'SP5'
	where info like ('%Microsoft Windows%Service Pack 5%') """)
	cur.execute("""UPDATE hosts SET os_sp = 'SP6'
	where info like ('%Microsoft Windows%Service Pack 6%') """)

	####Commit all changes above
	conn.commit()

	#Need to confirm that we are ONLY passing args (db_update)  and nothing else...
	if num_args > 1:
		if str(sys.argv[1]) == "db_update":
        		exit(0)
		else:
        		pass

##################END db_update(cur) FUNCTION##############################################


##################BEGIN cve_update(cur) FUNCTION###########################################
def cve_update(cur):
	cur.execute("""select name from refs where name like 'CVE%';""")
	NSSCVE="/nessus.cve.msf.txt"
	os.chdir("tmp/")
	NSSCVE=os.getcwd()+NSSCVE
	f=open(NSSCVE, 'r')
	datas=f.readlines()
	#print "DEBUG-NESSUS 1-->", datas
	datas_str=str(datas)
	#print "DEBUG-NESSUS 2-->", datas
	GOODCVE = ""
	GOODNSS = ""
	rows = cur.fetchall()

	for row in rows:
    		#print "DEBUG-Testing ", row[0]
    		if re.search(r"(?<=)%s" % row[0], datas_str, re.IGNORECASE):
        		#print "DEBUG-YES -- match found !!-- Test Value=", row[0], " Alldata=", datas_str
        		GOODCVE += row[0]
        		GOODCVE += "|"

    		else:
        		#print "DEBUG-NO -- match found!!-- Test Value=", row[0], " Alldata=", datas_str
        		pass
	#print "DEBUG-Good CVE = ", GOODCVE
	GOODCVES = GOODCVE.split('|')
	########next line is to remove the last entry in ARRAY which is not valid in the above loop
	GOODCVES.pop()
	#print "DEBUG-GOODCVE ARRAY", GOODCVES

	for data in datas:
		line = data.split(':')
		GOODNSS += line[0]
		GOODNSS += "|"
		print("DEBUG-NSS-->", line[0], "CVE-->",line[1])

	#print "DEBUG-GOOD NSS -->", GOODNSS	

	GOODNSSS = GOODNSS.split('|')
	########next 2 lines are to remove (pop) the last entry in ARRAY which is not valid in the above loop
	GOODNSSS.pop()
	GOODNSSS.pop()
	print( "DEBUG-GOODNSS ARRAY", GOODNSSS)

	####################################HERE's where we get the GOODNSSS variable
	###HOLDER FOR GOODNSSS REPORT!!
	SQLstring = ""
	for GOODNSS in GOODNSSS:
        	#Sample name = 'NSS-19402' or name = 'NSS-19408'
		SQLstring += "name = \'NSS-"
		SQLstring += GOODNSS
		SQLstring += "\' or "
		print( "DEBUG-growing-->", SQLstring)
	#Here we have to remove the last  ---> or 
	SQLstring = SQLstring[:-4]
	print( "DEBUG-sqlstring-",SQLstring)
	cur.execute("""Select DISTINCT H.address, H.name, concat('ALLNSS-MSF'), concat('?NSS-'), V.name, H.os_name from hosts H, vulns V, services S
	WHERE V.id in
	(Select vuln_id from vulns_refs where ref_id IN (Select id from refs where %s ))
	AND V.host_id = H.id;
	""" %\
	(SQLstring))
	rows = cur.fetchall()
	if rows:
        	print( "GAPING HOLE (ALLNSS)()() - msf> search cve:XXXXX")
	else:
        	pass
	for row in rows:
        	print("\t", row[0], "\t", row[1], "\t", row[4]," (",row[2],"/",row[3],")")



	#Need to confirm that we are ONLY passing args (cve_update)  and nothing else...
	if num_args > 1:
		if str(sys.argv[1]) == "cve_update":
			exit(0)
		else:
			pass
###################END cve_update(cur) FUNCTION###########################################33



if num_args > 1:
	if str(sys.argv[1]) == "db_update":
        	print( "only updating the DB")
        	db_update(cur)
	else:
		if str(sys.argv[1]) == "cve_update":
			print("only updating the CVE")
			cve_update(cur)
		else:
			pass

#ARGS passed


#Code to Run ALL the time....
db_update(cur)



###############################################
#SNIPER-OS-Listings
#print "==========Phase 5 - OS Listings=============="
#print "Would you like to breakdown known hosts by OS ? (y/N)"
#yes = set(['yes','y'])
#no = set(['no','n',''])
#choice = input().lower()
#if choice in yes:
#                print "(OK) Generating Host OS list"
#		#OS-MS Windows
#		print "--MS Windows HOSTS"
#		cur.execute("""SELECT DISTINCT address from hosts where state = 'alive' and os_name = 'Microsoft Windows' ORDER by address""")
#		rows = cur.fetchall()
#		for row in rows:
#		    countOS2 +=1
#		    print row[0]
#
#		#OS-SUN
#		print "--SUN HOSTS"
#		cur.execute("""SELECT DISTINCT address from hosts where state = 'alive' and os_name = 'Sun' ORDER by address""")
#		rows = cur.fetchall()
#		for row in rows:
#		    countOS2 +=1
#		    print row[0]
#
#		#OS-LINUX
#		print "--LINUX HOSTS"
#		cur.execute("""SELECT DISTINCT address from hosts where state = 'alive' and os_name = 'Linux' ORDER by address""")
#		rows = cur.fetchall()
#		for row in rows:
#		    countOS2 +=1
#		    print row[0]
#
#		#OS-FREEBSD
#		print "--FreeBSD HOSTS"
#		cur.execute("""SELECT DISTINCT address from hosts where state = 'alive' and os_name like '%reeBSD%' ORDER by address""")
#		rows = cur.fetchall()
#		for row in rows:
#		    countOS2 +=1
#		    print row[0]
#
#		#OS-CISCO
#		print "--Cisco HOSTS"
#		cur.execute("""SELECT DISTINCT address from hosts where state = 'alive' and os_name like '%Cisco%' ORDER by address""")
#		rows = cur.fetchall()
#		for row in rows:
#		    countOS2 +=1
#		    print row[0]
#
#		#OS-ESX
#		print "--ESX HOSTS"
#		cur.execute("""SELECT DISTINCT address from hosts where state = 'alive' and os_name like '%ESX%' ORDER by address""")
#		rows = cur.fetchall()
#		for row in rows:
#		    countOS2 +=1
#		    print row[0]
#
#		#OS-All others
#		print "--ALL OTHER HOSTS"
#		cur.execute("""SELECT DISTINCT address, os_name from hosts where state = 'alive' and os_name <> 'Sun' and os_name <> 'Microsoft Windows' and os_name <> 'Linux' and os_name not like '%reeBSD%' and os_name not like '%Cisco%' and os_name not like '%ESX%'  ORDER by address""")
#		rows = cur.fetchall()
#		for row in rows:
#		    countOS2 +=1
#		    print row[0], row[1]
#
#
#elif choice in no:
#                print "(OK) Skipping Host OS list"
#else:  
#                print "Please respond with 'yes' or 'no'"
#


#SNIPER-REPORT-Findings
print("Report Findings (by nmap)")

########################
#Here is beginiing of nmap results only (not nessus results)
cur.execute("""SELECT DISTINCT H.address, H.name ,S.name, S.port, H.os_name FROM hosts H, services S
WHERE (S.name like '%elnet%' and S.port = '23' and S.state = 'open') 
AND S.host_id = H.id
UNION ALL
/*Insecure Protocols TELNET(!23)*/
SELECT DISTINCT H.address, H.name ,S.name, S.port, H.os_name from hosts H, services S
WHERE (S.name like '%elnet%' and S.port <> '23' and S.info like '%elnet%' and S.state = 'open')
AND S.host_id = H.id 
UNION ALL
/*Insecure Protocols FTP(21) */
SELECT DISTINCT H.address, H.name ,S.name, S.port, H.os_name from hosts H, services S
WHERE (S.name like '%ftp%' and S.port = '21' and S.state = 'open')
AND S.host_id = H.id
UNION ALL
/*Insecure Protocols TFTP(69)*/
SELECT DISTINCT H.address, H.name ,S.name, S.port, H.os_name from hosts H, services S
WHERE (S.name like '%tftp%' and S.port = '69' and S.state = 'open')
AND S.host_id = H.id
UNION ALL
/*Insecure Protocols FINGER(79)*/
SELECT DISTINCT H.address, H.name ,S.name, S.port, H.os_name from hosts H, services S
WHERE (S.name like '%finger%' and S.port = '79' and S.state = 'open')
AND S.host_id = H.id
UNION ALL
/*Insecure Protocols CHARGEN(19)*/
SELECT DISTINCT H.address, H.name ,S.name, S.port, H.os_name from hosts H, services S
WHERE (S.name like '%chargen%' and S.port = '19' and S.state = 'open')
AND S.host_id = H.id
UNION ALL
/*Insecure Protocols RSH/Rlogin(513)*/
SELECT DISTINCT H.address, H.name ,S.name, S.port, H.os_name from hosts H, services S
WHERE (S.name like '%rlogin%' and S.port = '513' and S.state = 'open')
AND S.host_id = H.id
UNION ALL
/*Insecure Protocols POP(110)*/
SELECT DISTINCT H.address, H.name ,S.name, S.port, H.os_name from hosts H, services S
WHERE (S.name like '%pop%' and S.state = 'open')
AND S.host_id = H.id
UNION ALL
/*Insecure Protocols VNC(ANY)*/
SELECT DISTINCT H.address, H.name ,S.name, S.port, H.os_name from hosts H, services S
WHERE (S.info like '%VNC%rotocol%' and S.state = 'open')
AND S.host_id = H.id
UNION ALL
/*Insecure Protocols IMAP(143)*/
SELECT DISTINCT H.address, H.name ,S.name, S.port, H.os_name from hosts H, services S
WHERE (S.name like '%imap%' and S.state = 'open')
AND S.host_id = H.id
UNION ALL
/*Insecure Protocols SSHv1(ANY)*/
SELECT DISTINCT H.address, H.name ,concat('SSH', 'v1') as name, S.port, H.os_name from hosts H, services S
WHERE (S.info like '%SSH%rotocol%1.%' and S.state = 'open')
AND S.host_id = H.id

UNION ALL
-- /*Insecure Protocols HTTP(80)http (!VMk)*/
-- Select DISTINCT H.address, H.name, S.name, S.port, H.os_name from hosts H, services S 
-- WHERE (S.name like '%http%' and S.state = 'open' and S.name not like '%https%' and (S.port = '80') and H.os_name not like '%VMk%') 
-- AND S.host_id = H.id
-- UNION ALL
-- /*Insecure Protocols HTTP(80)www (!VMk)*/
-- Select DISTINCT H.address, H.name, S.name, S.port, H.os_name from hosts H, services S 
-- WHERE (S.name like '%www%' and S.state = 'open' and S.name not like '%https%' and (S.port = '80') and H.os_name not like '%VMk%') 
-- AND S.host_id = H.id
-- UNION ALL
/*Insecure Protocols SNMP v1/2*/
Select DISTINCT H.address, H.name, concat('SNMP', 'v1/2') as name, S.port, H.os_name from hosts H, services S 
WHERE (S.name like '%snmp%' and H.address in (Select DISTINCT H.address from hosts H, vulns V WHERE V.id in (Select vuln_id from vulns_refs where ref_id = (Select id from refs where name = 
'NSS-41028')) AND V.host_id = H.id)) 
AND S.host_id = H.id
ORDER by 3,5
""")
rows = cur.fetchall()
if rows:
	print("Insecure Protocols & Services (VulnDB=15)")
	print("Would you like to list Insecure Protocols & Services? (y/N)")
	yes = set(['yes','y'])
	no = set(['no','n',''])

	choice = input().lower()
	if choice in yes:
		for row in rows:
			print("Fix formatting",row[0], row[1], row[4],row[2],row[3])
		print("END -- Insecure Protocols")
	elif choice in no:
		pass
	else:
		print("Please respond with 'yes' or 'no'")

###########################################
print("Report Findings (by Nessus PluginID)")

nss_report(10079,'Anonymous FTP Enabled',221)
nss_report(41028,'SNMP Configured with Default RO/RW Community String (public)',38)
nss_report(12107,'Antivirus Definitions Not Updated: McAfee',14)
nss_report(35372,'DNS Unauthenticated Injection',191)
nss_report(10595,'DNS Unauthorized Zone Transfer (AXFR)',124)
nss_report(12217,'DNS Cache Snooping Remote Information Disclosure',190)
nss_report(10539,'DNS Recursive Query Cache Poisoning Weakness',192)
nss_report(20007,'Support for Weak Cryptographic Protocols or Ciphers: SSLv2',189)
nss_report(26925,'VNC Service Requires No Authentication',237)
nss_report(11459,'Last Logged User Name Disclosure',34)
nss_report(11422,'Default Installation Files on Web Server',159)
nss_report(34460,'End of Life Product: Web Server',213)
nss_report(47709,'End of Life Product: WIN2k',213)
nss_report(54581,'Anonymous SMTP Authentication Enabled',52)
nss_report(57582,'Self-signed Certificates',87)
nss_report(42256,'Anonymous READ Access to NFS Shares',108)
nss_report(10249,'SMTP EXPN/VRFY Commands are Enabled',121)
nss_report(10172,'Network HP LaserJet Printer Allows Unauthenticated Access',123)
nss_report(11040,'Reverse Proxy Not Properly Restricted',160)
nss_report(11026,'Rogue Wireless Access Point Detection',239)
nss_report(40477,'Rogue Modem Installation Detection',39)
nss_report(35029,'Web Application: Default Username and Password (DRAC Default Password root/calvin)',223)
nss_report(19552,'Web Server Information Disclosure: McAfee EPO',92)
#Rarely Reported --> nss_report(30218,'Windows not Configured for FIPS Compliance: Terminal Services',188)


###############################
print("Report Findings (by Nessus Compliance)")

cur.execute("""Select DISTINCT H.address, H.name, H.os_name from hosts H, vulns V 
WHERE H.os_name not like '%icrosoft%' and H.id in 
(SELECT V.host_id from Vulns V where V.info like '%8.3%Account%Expiration%' and V.name like '%nix%ompliance%' and V.info like '%Remote%' and V.info like '%Password length%than equal %." : [FAILED]%') 
AND V.host_id = H.id;
""")
rows = cur.fetchall()
if rows:
	print("UNIX- Password Policy - local password length less than 8 ---- Unix Compliance (Keyword)")
else:
	pass
for row in rows:
	print(row[0], row[1], row[2])
#################
cur.execute("""Select DISTINCT H.address, H.name, H.os_name from hosts H, vulns V
WHERE H.os_name not like '%icrosoft%' and H.id in 
(SELECT V.host_id from Vulns V where V.info like '%8.3%Account%Expiration%' and V.name like '%nix%ompliance%' and V.info like '%Remote%' and V.info like '%Maximum Password Age less than equal 90." : [FAILED]%')
AND V.host_id = H.id;""")
rows = cur.fetchall()
if rows:
	print("UNIX- Password Policy - local password Age less than 90 day ---- Unix Compliance (Keyword)")
else:
	pass
for row in rows:
	print( row[0], row[1], row[2])
#####################

cur.execute("""Select DISTINCT H.address, H.name, H.os_name from hosts H, vulns V
WHERE H.os_name not like '%icrosoft%' and H.id in
(SELECT V.host_id from Vulns V where V.info like '%GEN001020%' and V.name like '%nix%ompliance%' and V.info like '%3.2.1.38%' and V.info like '%FAIL & root <> console%')
AND V.host_id = H.id;""")
rows = cur.fetchall()
if rows:
	print( "(Not confirmed-maybe broken need data) UNIX- Remote Root Login (Shared admin account) ---- Unix Compliance (Keyword) (VulnDB=65)")
else:
	pass
for row in rows:
	print( row[0], row[1], row[2])

###################################
##print "'GAPING HOLE' Report Findings (by Nessus PluginID)"

nss_report(63522,'GAPING HOLE (CLIENT SIDE) (MS13-008)(IE-CButton)  - msf> use exploit/windows/browser/ie_cbutton_uaf - seen false positive when IE7 not IE8',194)
nss_report(44110,'GAPING HOLE (CLIENT SIDE) (MS10-002)(IE-Aurora) - msf> use exploit/windows/browser/ms10_002_aurora',194)
nss_report(26187,'GAPING HOLE (CLIENT SIDE) IBM Tivoli Storage Manager - MSF> use exploit/windows/misc/ibm_tsm_cad_ping (or ../http/ibm_tsm_cad_header)',219)
nss_report(77823,'GAPING HOLE (SERVER SIDE) SHELLSHOCK - msf> search shellshock',000)
#########################
#HERE WE NEED FUNCTION for multiple NSS plugin IDS..

#/* MS08-067 suspected false positive w/ NSS-34477 */
cur.execute("""Select DISTINCT H.address, H.name, concat('MS08-067'), concat('?'), H.os_name from hosts H, vulns V, services S 
WHERE V.id in
(Select vuln_id from vulns_refs where ref_id IN (Select id from refs where name = 'NSS-34476' or name = 'NSS-34821' or name = 'NSS-34477'))
AND V.host_id = H.id;
""")
rows = cur.fetchall()
if rows:
	print( "GAPING HOLE (REMOTE SERVER EXPLOIT) (WINDOWS netapi-RPC) - msf> use exploit/windows/smb/ms08_067_netapi (NessusPluginID=34476, 34821, 34477(uncred))")
else:   
        pass
for row in rows:
	print( "\t", row[0], "\t", row[1], "\t", row[4]," (",row[2],"/",row[3],")")
###############
#/* MS06-040 suspected false positive w/ NSS-22194 */
cur.execute("""Select DISTINCT H.address, H.name, concat('MS06-040'), concat('?'), H.os_name from hosts H, vulns V, services S
WHERE V.id in
(Select vuln_id from vulns_refs where ref_id IN (Select id from refs where name = 'NSS-22182' or name = 'NSS-22194'))
AND V.host_id = H.id;
""")
rows = cur.fetchall()
if rows:
	print( "GAPING HOLE (REMOTE SERVER EXPLOIT) (WINDOWS netapi)- msf> use exploit/windows/smb/ms06_040_netapi (NessusPluginID=22182,22194(uncred))")
else:  
        pass
for row in rows:
	print( "\t", row[0], "\t", row[1], "\t", row[4]," (",row[2],"/",row[3],")")
################
#/* MS03-026 suspected false positive w/ NSS-11808 */
cur.execute("""Select DISTINCT H.address, H.name, concat('MS03-026'), concat('?'), H.os_name from hosts H, vulns V, services S
WHERE V.id in
(Select vuln_id from vulns_refs where ref_id IN (Select id from refs where name = 'NSS-11790' or name = 'NSS-11808'))
AND V.host_id = H.id;
""")
rows = cur.fetchall()
if rows:
	print( "GAPING HOLE (REMOTE SERVER EXPLOIT) (WINDOWS DCOM) - msf> use exploit/windows/dcerpc/ms03_026_dcom (NessusPluginID=11790,11808(uncred))")
else: 
        pass
for row in rows:
	print( "\t", row[0], "\t", row[1], "\t", row[4]," (",row[2],"/",row[3],")")
################
#/* Embedded Windows PDF exploit */
cur.execute("""Select DISTINCT H.address, H.name, concat('Adobe-'), concat('PDF'), H.os_name from hosts H, vulns V, services S
WHERE V.id in
(Select vuln_id from vulns_refs where ref_id IN (Select id from refs where name = 'NSS-47164' or name = 'NSS-47165' or name = 'NSS-48374' or name = 'NSS-48375'))
AND V.host_id = H.id;
""")
rows = cur.fetchall()
if rows:
	print("GAPING HOLE (CLIENT SIDE) (Adobe PDF Windows)- msf> use exploit/windows/fileformat/adobe_pdf_embedded_exe* (NessusPluginID=47164,47165,48374,48375)")
else:  
        pass
for row in rows:
	print("\t", row[0], "\t", row[1], "\t", row[4]," (",row[2],"/",row[3],")")
################
#/* Java Atomic Reference (probably Windows) */
cur.execute("""Select DISTINCT H.address, H.name, concat('Java-Atomic'), concat('Windows'), H.os_name from hosts H, vulns V, services S
WHERE V.id in
(Select vuln_id from vulns_refs where ref_id IN (Select id from refs where name = 'NSS-57959' or name = 'NSS-64847' or name = 'NSS-66806'))
AND V.host_id = H.id;
""")
rows = cur.fetchall()
if rows:
	print("GAPING HOLE (CLIENT SIDE) (Java Atomic Ref -likely WINDOWS) - msf> use exploit/multi/browser/java_atomicreferencearray (NessusPluginID=57959,64847,66806)")
else: 
	pass
for row in rows:
	print( "\t", row[0], "\t", row[1], "\t", row[4]," (",row[2],"/",row[3],")")
################
#/* Java Atomic Reference (*NIX) */
cur.execute("""Select DISTINCT H.address, H.name, concat('Java-Atomic'), concat('UNIX'), H.os_name from hosts H, vulns V, services S
WHERE V.id in
(Select vuln_id from vulns_refs where ref_id IN (Select id from refs where name = 'NSS-57956' or name = 'NSS-57961' or name = 'NSS-57991' or name = 'NSS-58084' or name = 'NSS-58130' or name = 'NSS-58148' or name = 'NSS-58179' or name = 'NSS-58605' or name = 'NSS-58606' or name = 'NSS-58840' or name = 'NSS-58866' or name = 'NSS-64164' or name = 'NSS-68459' or name = 'NSS-68487'))
AND V.host_id = H.id;
""")
rows = cur.fetchall()
if rows:
	print("GAPING HOLE (CLIENT SIDE) (Java Atomic Ref (*NIX)) - msf> use exploit/multi/browser/java_atomicreferencearray (NessusPluginID=57956,57961,57991,58084,58130,58148,58179,58605,58606,58840,58866,64164,68459,68487)")
else: 
        pass
for row in rows:
	print("\t", row[0], "\t", row[1], "\t", row[4]," (",row[2],"/",row[3],")")
################
#/* MS05-039 potential false positive 19408*/
cur.execute("""Select DISTINCT H.address, H.name, concat('MS05-039'), concat('?'), H.os_name from hosts H, vulns V, services S
WHERE V.id in
(Select vuln_id from vulns_refs where ref_id IN (Select id from refs where name = 'NSS-19402' or name = 'NSS-19408'))
AND V.host_id = H.id;
""")
rows = cur.fetchall()
if rows:
	print("GAPING HOLE (MS05-039) - msf> use exploit/multi/browser/java_atomicreferencearray (NessusPluginID=19402,19408)")
else:
	pass
for row in rows:
	print( "\t", row[0], "\t", row[1], "\t", row[4]," (",row[2],"/",row[3],")")
################
#########OTHERS for consideration with msf exploits (see exploitdb and sort by metasploit)
#vuln			CVE  		NSS
#adobe reader		2013-3346	66409
#ms13-090 (activex)	2013-3918	70848
#nas4free		2013-3631	not out
#MS13-080		2013-3897	70332
#phpMyAdmin 3/4		2013-3238	66295
#FlashPlayer<11.3.300x	2012-1535	61550


############################
#print "'GAPING HOLE' Report Findings (by Nessus Compliance)"

cur.execute("""Select DISTINCT H.address, H.name, H.os_name from hosts H, vulns V
WHERE H.os_name not like '%icrosoft%' and H.id in 
(SELECT V.host_id from Vulns V where V.info like '%hosts.equiv%' and V.name like '%nix%ompliance%' and V.info like '%3.2.1.85%' and V.info like '%hosts.equiv%[FAILED]%')
AND V.host_id = H.id;""")
rows = cur.fetchall()
if rows:
	print("GAPING HOLE Root Login Allowed Without a Password - (rshd & + in hosts.equiv)  (from Nessus Compliance)")
else:
	pass
for row in rows:
	print( row[0], "\t", row[1], "\t", row[2])


###################################
#SNIPER/NESSUS ERRORS,etc below
#####################################


#DUPLICATE MAC addresses (clustering example) fix to test is the where mac <> ' '
cur.execute("""select address, name, hosts.mac FROM hosts INNER JOIN (SELECT mac FROM hosts where mac <> ' ' GROUP BY mac HAVING count(mac) > 1) dup ON hosts.mac = dup.mac""")
rows = cur.fetchall()
if rows:
	print("Would you like to examine hosts with Duplicate MAC addresses? (y/N)")
	yes = set(['yes','y'])
	no = set(['no','n',''])

	choice = input().lower()
	if choice in yes:
		for row in rows:
			print(row[0], "\t", row[1], "\t", row[2])
		print("END -- DUPLICATE MAC Addresses/Issues above - may want to remove duplicates to prevent redundancy")
	elif choice in no:
		pass
	else:
		print("Please respond with 'yes' or 'no'")
else:
	pass


#UNKNOWN HOSTS - manual review
cur.execute("""select h.address, s.port, s.name, s.info from hosts h FULL join services s on h.id = s.host_id where (h.os_name = 'Unknown' and s.info <> '')""")
rows = cur.fetchall()
if rows:
	print("Would you like to examine Unknown Host OS's ? (y/N)")
	yes = set(['yes','y'])
	no = set(['no','n',''])

	choice = input().lower()
	if choice in yes:
		for row in rows:
			print( row[0], "\t", row[1], "\t", row[2], "\t", row[3])
		print("END -- UNKNOWN Host OS above - may want to investigate")
	elif choice in no:
		pass
	else:
		print( "Please respond with 'yes' or 'no'")
else:
	pass





############################
#####Nessus Credential Issues below:
cur.execute("""Select DISTINCT H.address, H.os_name, V.name from hosts H, vulns V WHERE V.id in (Select vuln_id from vulns_refs where ref_id = (Select id from refs where name = 'NSS-21745')) AND V.host_id = H.id;
""")
rows = cur.fetchall()
if rows:
	print( "Nessus was unable to authenticate on the following hosts - CHECK credentials!!---- NessusID=21745")
	for row in rows:
		print( "\t", row[0], row[1])
	print( "Would you like to clear the 21745 results above? (y/N)")
	yes = set(['yes','y'])
	no = set(['no','n',''])

	choice = input().lower()
	if choice in yes:
		cur.execute("""DELETE FROM vulns V WHERE V.id in (Select vuln_id from vulns_refs where ref_id = (Select id from refs where name = 'NSS-21745'))
		""")
		print( "Ok - Cleared hosts from database")
	elif choice in no:
        	print( "Ok - keeping problem hosts ")
	else:  
        	print( "Please respond with 'yes' or 'no'")
else:
	pass
####################
#UNIX login, but without admin (root) priv's

cur.execute("""Select DISTINCT H.address, H.name, H.os_name from hosts H, vulns V
WHERE H.os_name not like '%icrosoft%' and H.id in
(SELECT V.host_id from Vulns V where V.info like '%audit check is not running as root%')
AND V.host_id = H.id;
""")
rows = cur.fetchall()
if rows:
	print( "Your nessus scan logged in with ssh, but did not have root priv's (sudo,etc)")
else:
	pass
for row in rows:
	print( "\t", row[0], row[1], row[2])
#########
# Make changes to the database persistent
#Next line below may not be needed as long as the above update, create, deletes are commited
conn.commit()

# Close communication with the postgres database
cur.close()
conn.close()


