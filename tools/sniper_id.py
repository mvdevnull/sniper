#!/usr/bin/python
import psycopg2
import os
import re

#dbpass = '6Ja1xODwesQjtxtWF85E8MhNiY1g7lizc+iBQRMmED8='   #alternatively place password manually on this line
dbpass = os.popen("cat /usr/share/metasploit-framework/config/database.yml | grep -m1 password | cut -d \":\" -f 2 | awk '{ gsub (\" \", \"\", $0); print}'").read()
constring = "dbname='msf' user='msf' host='localhost' port='5432' password='"+str(dbpass)+"'"
constring = constring.replace('\n', '')


#CONNECT TO DB
#CONNECT TO DB
try:
    conn = psycopg2.connect(constring)


except:
    print "Error: Unable to connect to the database"

cur = conn.cursor()

#
pid = "NSS-"
pid += str(input("Enter the Nessus Plugin ID you are interested in\n"))

cur.execute("""Select DISTINCT H.address, H.name, H.os_name, V.name from hosts H, vulns V WHERE V.id in (Select vuln_id from vulns_refs where ref_id = (Select id from refs where name = %s)) AND V.host_id = H.id;""",
([pid]))


rows = cur.fetchall()
for row in rows:
    print row[0], "\t\t", row[1], "\t\t", row[2]
    print "End of (", pid, ")", row[3]




conn.commit()
cur.close()
conn.close()
