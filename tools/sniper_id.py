#!/usr/bin/python
import psycopg2
#CONNECT TO DB
#CONNECT TO DB
try:
    conn = psycopg2.connect("dbname='msf' user='msf' host='localhost' port='5432' password='ffGdwOS40ByPi2Pp7RKDStDabxMjgGlC'")


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
