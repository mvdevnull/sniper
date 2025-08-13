#!/usr/bin/python3
#Script - sniper.py 
#Description - script used for DISCOVERY, various targeted nessus scans and Reports.
#Author - chrisdhebert@gmail.com
#Version - 2.2021-02-25

import psycopg2
import sys
import os
import re
import csv

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
#OS Updates via services Function
def load_os_updates(filename='conf/os_rules.csv'):
        validation_errors = validate_os_csv_format(filename)
        if validation_errors:
        	print("CSV Validation Errors:")
        	for error in validation_errors:
        		print(f"  ERROR: {error}")
        	raise ValueError(f"CSV file '{filename}' has validation errors. Please fix before proceeding.")
        updates = []
        with open(filename, 'r') as f:
        	reader = csv.DictReader(f)
        	for row in reader:
        		if row['os_name'].strip():
        			updates.append(row)
        return updates

def apply_os_updates(cur):
        updates = load_os_updates()

        for rule in updates:
        	conditions = []
        	if rule['port'] and rule['port'] != '%':
        		conditions.append(f"port = '{rule['port']}'")
        	if rule['service_name'] and rule['service_name'] != '%':
        		conditions.append(f"name = '{rule['service_name']}'")
        	if rule['info_pattern'] and rule['info_pattern'] != '%':
        		conditions.append(f"info like ('{rule['info_pattern']}')")

        	service_where = " and ".join(conditions) if conditions else "1=1"

        	# Build UPDATE query
        	set_clause = f"os_name = '{rule['os_name']}', comments = 'OS-Updated-by-sniper.py'"
        	if rule['os_flavor']:
        		set_clause += f", os_flavor = '{rule['os_flavor']}'"

        	where_clause = f"id in (SELECT host_id from services where {service_where})"
        	if rule['prev_os_name']:
        		where_clause += f" and os_name = '{rule['prev_os_name']}'"

        	query = f"UPDATE hosts SET {set_clause} WHERE {where_clause}"
        	#print ("DEBUG-",query)
        	cur.execute(query)

def validate_os_csv_format(filename='conf/os_rules.csv'):
        errors = []
        line_num = 0

        try:
        	with open(filename, 'r') as f:
        		lines = f.readlines()

        	# Check if file is empty
        	if not lines:
        		errors.append("CSV file is empty")
        		return errors

        	for line_num, line in enumerate(lines, 1):
        		line = line.strip()
        		if not line:  # Skip empty lines
        			continue
        		# Count commas - should be exactly 5 (for 6 columns)
        		comma_count = line.count(',')
        		if comma_count != 5:
        			errors.append(f"Line {line_num}: Expected 5 commas, found {comma_count} - '{line}'")
        			continue
        		fields = line.split(',')
        		# Skip header line
        		if line_num == 1:
        			continue
        		# Check required fields - os_name must not be empty
        		os_name = fields[0]
        		if not os_name.strip():
        			errors.append(f"Line {line_num}: 'os_name' is required")
        		# Port validation - should be numeric or empty
        		port = fields[2]
        		if port.strip() and not port.strip().isdigit():
        			errors.append(f"Line {line_num}: 'port' must be numeric or empty, got '{port}'")
        		# Check for unescaped quotes or special chars
        		if "'" in line and line.count("'") % 2 != 0:
        			errors.append(f"Line {line_num}: Unmatched single quote in line")

        except FileNotFoundError:
        	errors.append(f"CSV file '{filename}' not found")
        except Exception as e:
        	errors.append(f"Error reading CSV file: {str(e)}")

        return errors

##############################################
#OS Updates via eyewitness Function
def load_eyewitness_updates(filename='conf/eyewitness_rules.csv'):
        validation_errors = validate_eyewitness_csv_format(filename)
        if validation_errors:
        	print("Eyewitness CSV Validation Errors:")
        	for error in validation_errors:
        		print(f"  ERROR: {error}")
        	raise ValueError(f"CSV file '{filename}' has validation errors.")

        updates = []
        with open(filename, 'r') as f:
        	reader = csv.DictReader(f)
        	for row in reader:
        		if row['os_name'].strip():
        			# Convert string 'True'/'False' to boolean
        			row['only_unknown'] = row['only_unknown'].strip().lower() == 'true'
        			updates.append(row)
        return updates

def apply_eyewitness_updates(cur):
        if not (os.path.isdir("./eyewitness/source/") and len(os.listdir("./eyewitness/source/")) > 0):
        	print("No Eyewitness results found - skipping..")
        	return

        print("Eyewitness results found - processing known OS hosts..")
        updates = load_eyewitness_updates()

        for rule in updates:
        # Extract IPs using grep pattern
        cmd = f"grep -i '{rule['grep_pattern']}' ./eyewitness/source/* | cut -d ':' -f1 | grep -Eo
  '([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}'"
        ips = os.popen(cmd).read().strip()
        ip_list = [ip for ip in ips.split('\n') if ip]

        for ip in ip_list:
        	# Build SET clause
        	set_clause = f"os_name = '{rule['os_name']}', comments = 'OS-Updated-by-sniper-eyewitness.py'"
        	if rule['os_flavor']:
        		set_clause += f", os_flavor = '{rule['os_flavor']}'"
        	if rule['info']:
        		set_clause += f", info = '{rule['info']}'"
        	if rule['purpose']:
        		set_clause += f", purpose = '{rule['purpose']}'"

        	# Build WHERE clause
        	where_clause = f"address = '{ip}'"
        	if rule['only_unknown']:
        		where_clause += " and os_name = 'Unknown'"

        	query = f"UPDATE hosts SET {set_clause} WHERE {where_clause}"
        	cur.execute(query)

def validate_eyewitness_csv_format(filename='conf/eyewitness_rules.csv'):
      """Validate eyewitness CSV format"""
        errors = []
        try:
        	with open(filename, 'r') as f:
        		lines = f.readlines()

        	for line_num, line in enumerate(lines, 1):
        		line = line.strip()
        		if not line:
        			continue

        	# Should have exactly 5 commas (6 fields)
        	if line.count(',') != 5:
        		errors.append(f"Line {line_num}: Expected 5 commas, found {line.count(',')} - '{line}'")
        		continue

        	if line_num == 1:  # Skip header
        		continue

        	fields = line.split(',')
        	os_name, os_flavor, grep_pattern, info, purpose, only_unknown = fields

        	if not os_name.strip():
        		errors.append(f"Line {line_num}: 'os_name' is required")
        	if not grep_pattern.strip():
        		errors.append(f"Line {line_num}: 'grep_pattern' is required")
        	if only_unknown.strip().lower() not in ['true', 'false', '']:
        		errors.append(f"Line {line_num}: 'only_unknown' must be 'True' or 'False'")

        except FileNotFoundError:
        	errors.append(f"CSV file '{filename}' not found")
        except Exception as e:
        	errors.append(f"Error reading CSV file: {str(e)}")

        return errors

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
	#OS UPDATES via os_rules.csv
	apply_os_updates(cur)


	####################################################
	#OS UPDATES via eyewitness information
	apply_eyewitness_updates(cur)
	"""
	if os.path.isdir("./eyewitness/source/") and len(os.listdir("./eyewitness/source/")) > 0:
		print("Eyewitness results found -  processing known OS hosts..")
		#IDRAC9 via eyewitness
		idrac9 = os.popen(r"grep -i 'Integrated Remote Access Controller 9' ./eyewitness/source/* | cut -d ':' -f1 |grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'").read().strip()
		idrac9 = idrac9.split('\n')
		idrac9 = [ip for ip in idrac9 if ip]
		for ip in idrac9:
			cur.execute("""UPDATE hosts SET os_name = 'DELL iDRAC 9', comments = 'OS-Updated-by-sniper-eyewitness.py'
	  		where address = '%s' and os_name = 'Unknown'"""%\
				   (ip))
	
		#Hanwha Vision Cameras via eyewitness
		hanwha = os.popen(r"grep -i 'Hanwha Vision WebViewer' ./eyewitness/source/* | cut -d ':' -f1 |grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'").read().strip()
		hanwha = hanwha.split('\n')
		hanwha = [ip for ip in hanwha if ip]
		for ip in hanwha:
			cur.execute("""UPDATE hosts SET os_name = 'Hanwha Vision', os_flavor = 'camera', comments = 'OS-Updated-by-sniper-eyewitness.py'
	  		where address = '%s' and os_name = 'Unknown'"""%\
				   (ip))
			
		#Pelco Sarix Pro Cameras via eyewitness
		sarix = os.popen(r"grep -i 'title>Sarix Pro' ./eyewitness/source/* | cut -d ':' -f1 |grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'").read().strip()
		sarix = sarix.split('\n')
		sarix = [ip for ip in sarix if ip]
		for ip in sarix:
			cur.execute("""UPDATE hosts SET os_name = 'Pelco Sarix Pro', os_flavor = 'camera', comments = 'OS-Updated-by-sniper-eyewitness.py'
	  		where address = '%s' and os_name = 'Unknown'"""%\
				   (ip))
	
		#BARIX Barionet 50 IO via eyewitness
		barix = os.popen(r"grep -i 'title>BARIX Barionet 50' ./eyewitness/source/* | cut -d ':' -f1 |grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'").read().strip()
		barix = barix.split('\n')
		barix = [ip for ip in barix if ip]
		for ip in barix:
			cur.execute("""UPDATE hosts SET os_name = 'BARIX Barionet 50', os_flavor = 'I/O', comments = 'OS-Updated-by-sniper-eyewitness.py'
	  		where address = '%s' and os_name = 'Unknown'"""%\
				   (ip))
	
		#Cisco UCS KVM Direct KVM via eyewitness
		ciscoucs = os.popen(r"grep -i 'title>Cisco UCS KVM Direct' ./eyewitness/source/* | cut -d ':' -f1 |grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'").read().strip()
		ciscoucs = ciscoucs.split('\n')
		ciscoucs = [ip for ip in ciscoucs if ip]
		for ip in ciscoucs:
			cur.execute("""UPDATE hosts SET os_name = 'Cisco UCS KVM Direct', os_flavor = 'KVM', comments = 'OS-Updated-by-sniper-eyewitness.py'
	  		where address = '%s' and os_name = 'Unknown'"""%\
				   (ip))
		
		#iSTAR Ultra controller via eyewitness
		istar = os.popen(r"grep -i '>iSTAR Ultra' ./eyewitness/source/* | cut -d ':' -f1 |grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'").read().strip()
		istar = istar.split('\n')
		istar = [ip for ip in istar if ip]
		for ip in istar:
			cur.execute("""UPDATE hosts SET os_name = 'iSTAR Ultra', os_flavor = 'I/O controller', comments = 'OS-Updated-by-sniper-eyewitness.py'
	  		where address = '%s' and os_name = 'Unknown'"""%\
				   (ip))
	
		#Pelco Endura camera via eyewitness
		endura = os.popen(r"grep -i 'tle>Endura' ./eyewitness/source/* | cut -d ':' -f1 |grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'").read().strip()
		endura = endura.split('\n')
		endura = [ip for ip in endura if ip]
		for ip in endura:
			cur.execute("""UPDATE hosts SET os_name = 'Pelco Endura camera', os_flavor = 'camera', info = 'unauth liveview', comments = 'OS-Updated-by-sniper-eyewitness.py'
	  		where address = '%s' and os_name = 'Unknown'"""%\
				   (ip))
			
		#NETAPP ONtap Storage via eyewitness
		ontap = os.popen(r"grep -i 'ONTAP System Manager' ./eyewitness/source/* | cut -d ':' -f1 |grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'").read().strip()
		ontap = ontap.split('\n')
		ontap = [ip for ip in ontap if ip]
		for ip in ontap:
			cur.execute("""UPDATE hosts SET os_name = 'NETAPP ONTAP', os_flavor = 'storage', comments = 'OS-Updated-by-sniper-eyewitness.py'
	  		where address = '%s' and os_name = 'Unknown'"""%\
				   (ip))
			
		#Zebra Printer via eyewitness
		zebra = os.popen(r"grep -i 'www.zebra.com' ./eyewitness/source/* | cut -d ':' -f1 |grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'").read().strip()
		zebra = zebra.split('\n')
		zebra = [ip for ip in zebra if ip]
		for ip in zebra:
			cur.execute("""UPDATE hosts SET os_name = 'Zebra Printer', os_flavor = 'printer', info = 'admin:1234', purpose = 'printer', comments = 'OS-Updated-by-sniper-eyewitness.py'
	  		where address = '%s' """%\
				   (ip))
	
		#Hanwha Vision Camera via eyewitness
		han2 = os.popen(r"grep -i 'Wisenet WEBVIEWER' ./eyewitness/source/* | cut -d ':' -f1 |grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'").read().strip()
		han2 = han2.split('\n')
		han2 = [ip for ip in han2 if ip]
		for ip in han2:
			cur.execute("""UPDATE hosts SET os_name = 'Hanwha Vision - Wisenet ', os_flavor = 'camera', purpose = 'camera', comments = 'OS-Updated-by-sniper-eyewitness.py'
	  		where address = '%s' """%\
				   (ip))
	else:
		print("No Eyewitness results found -  skipping..")
		



	
	####Commit all changes above
	conn.commit()
	"""
 
	#Need to confirm that we are ONLY passing args (db_update)  and nothing else...
	if num_args > 1:
		if str(sys.argv[1]) == "db_update":
        		exit(0)
		else:
        		pass

##################END db_update(cur) FUNCTION##############################################

if num_args > 1:
	if str(sys.argv[1]) == "db_update":
        	print( "only updating the DB")
        	db_update(cur)
	else:
		pass

#ARGS passed


#Code to Run ALL the time....
db_update(cur)


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
-- WHERE (S.name like '%www%' and S.port <> '443' and S.state = 'open' and S.name not like '%https%' and (S.port = '80') and H.os_name not like '%VMk%') 
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
	#print("Insecure Protocols & Services")
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
else:
	pass

########################
#Here is beginiing of nmap unpatch/outdated results only (not nessus results)
#/*Unpatched/Outdated Service MSSQL (1433)*/
cur.execute("""SELECT DISTINCT H.address, S.port, H.name ,S.name, H.os_name, S.info FROM hosts H, services S
WHERE (S.port = '1433' and S.info like '%SQL%Server%2016%' and S.state = 'open') 
AND S.host_id = H.id
UNION ALL
/*Unpatched/Outdated Service Holder for next  ABC (6666)*/
SELECT DISTINCT H.address, S.port, H.name ,S.name, H.os_name, S.info FROM hosts H, services S
WHERE (S.name like '%tbd%' and S.port = '6666' and S.info like '%tbdL%tbd%tbd%' and S.state = 'open') 
AND S.host_id = H.id
""")
rows = cur.fetchall()
if rows:
	#print("Unpatched/Outdated Services")
	print("Would you like to list Unpatched/Outdated Services? (y/N)")
	yes = set(['yes','y'])
	no = set(['no','n',''])

	choice = input().lower()
	if choice in yes:
		for row in rows:
			print(row[0], "(tcp/",row[1],")", row[5])
		print("END -- Unpatched/Outdated Services")
	elif choice in no:
		pass
	else:
		print("Please respond with 'yes' or 'no'")
else:
	pass





###########################################
#print("Report Findings (by Nessus PluginID)")
print("Would you like to list Nessus Findings? (y/N)")
yes = set(['yes','y'])
no = set(['no','n',''])

choice = input().lower()
if choice in yes:
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
	print("END -- Nessus Findings")
elif choice in no:
	pass
else:
	print("Please respond with 'yes' or 'no'")


###############################
#print("Report Findings (by Nessus Compliance)")
print("Would you like to list Nessus Compliance Findings? (y/N)")
yes = set(['yes','y'])
no = set(['no','n',''])

choice = input().lower()
if choice in yes:
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
	
	print("END -- Nessus Compliance Findings")
elif choice in no:
	pass
else:
	print("Please respond with 'yes' or 'no'")



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


