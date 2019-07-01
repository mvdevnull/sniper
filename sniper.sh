#!/bin/bash

#Author - chrisdhebert@gmail.com
#Version - 2.2019-07-01

clear

CWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
MSFBIN="/usr/bin/msfconsole"
EYEWITNESS="/usr/bin/eyewitness"
DB='msf'

SERVICE='postgresql'
if ps ax | grep -v grep | grep $SERVICE > /dev/null
then
        echo "(OK) - Found $SERVICE service running"
else
        echo "(OK) - Starting $SERVICE .... "
        /etc/init.d/$SERVICE start
        echo "(OK) - Starting $SERVICE service -- `ps ax | grep -v grep | grep $SERVICE`"
fi

if test -f "$EYEWITNESS"; then
    echo "(OK0 - Found $EYEWITNESS "
else
    echo "(ERROR) - eyewitness not found - install eyewitness (ex: apt-get install eyewitness)"
fi

echo '  _________      .__                     ' 
echo ' /   _____/ ____ |__|_____   ___________ '
echo ' \_____  \ /    \|  \____ \_/ __ \_  __ \'
echo ' /        \   |  \  |  |_> >  ___/|  | \/'
echo '/_______  /___|  /__|   __/ \___  >__|   '
echo '        \/     \/   |__|        \/       '


#Copying all known Nmap 
RESULTS=$CWD/results
CONF=$CWD/conf

#this is needed only if we call msfconsole as opposed to nc to msfd on localhost: 55554
cp $CONF/msf_default.rc $CONF/msf.rc



#Here is where we make msfd a "tiny" bit faster...by
##Getting rid of all metasploit banners!!!!
echo /usr/share/metasploit-framework/data/logos/*.txt | xargs -n1 cp /dev/null


#Only import files if we have new ones

if ls $RESULTS/new/*.* &> /dev/null; then
		echo "(OK) - Importing only newer NMAP to $DB database - (all Nmap output in ./new directory to $DB...)"
		/bin/cp $CONF/msf_default.rc $CONF/msf.rc
		echo "db_import $RESULTS/new/*.xml" >> $CONF/msf.rc
		echo "quit -y" >> $CONF/msf.rc
		$MSFBIN -r $CONF/msf.rc
		mv $RESULTS/new/*.xml $RESULTS/import_complete
		echo "(OK) - NMAP - DB Import Complete..."
		/usr/bin/python $CWD/tools/sniper.py db_update
else
		echo "(OK) - No new nmap files found in ./new directory to import"
fi

############################################
#Required so that postgres user has access to $CWD change after command
TOTALHOSTS=0
cd /tmp
TOTALHOSTS="$(/usr/bin/sudo -u postgres psql -d $DB -c """Select count(*) from hosts;""" | grep row -B 1| grep -v row)"
cd $CWD

#####Do a Quick & efficient NMAP discovery##########
echo "============Phase 1 Discovery - Nmap -Pn -n -v --disable-arp-ping -p 22,80,443,445 Scan ()=========="

if [ $TOTALHOSTS -eq "0" ] ; then
	echo "(Not OK!!) You have *NO* hosts in the database $DB. Enter the IP Range for QUICK host discovery? [Nmap compatible example - 192.168.1.1-200]"
    	read IPRANGE
	echo "(OK) Starting Discovery - Nmap -Pn -n -v --disable-arp-ping -p 22,80,443,445 Scan ()=========="
	/bin/cp $CONF/msf_default.rc $CONF/msf.rc
        echo "db_nmap -Pn -n -v --disable-arp-ping -p 22,80,443,445 $IPRANGE " >> $CONF/msf.rc
        echo "quit -y" >> $CONF/msf.rc
        $MSFBIN -r $CONF/msf.rc

	#We do this to remove filtered ports
        /usr/bin/python $CWD/tools/sniper.py db_update
	echo "(OK) - db_nmap -Pn -n -v --disable-arp-ping -p 22,445 Scan Complete..."

else
	echo "(OK) $TOTALHOSTS Total hosts in database $DB."
	read -p "(?) Do you want nmap to perform a 2nd discovery scan?(y/N)" yn

		case $yn in
                	[Yy]* ) echo "Enter the IP Range for QUICK host discovery? [Nmap compatible example - 192.168.1.1-200]";
                	read IPRANGE;
			echo "(OK) Starting 2nd Discovery scan - Nmap -Pn -n -v --disable-arp-ping -p 22,80,443,445 Scan ()==========";
        		/bin/cp $CONF/msf_default.rc $CONF/msf.rc;
        		echo "db_nmap -Pn -n -v --disable-arp-ping -p 22,80,443,445 $IPRANGE " >> $CONF/msf.rc;
        		echo "quit -y" >> $CONF/msf.rc;
        		$MSFBIN -r $CONF/msf.rc;

			#We do this to remove filtered ports
        		/usr/bin/python $CWD/tools/sniper.py db_update;
        		echo "(OK) - db_nmap -Pn -n -v --disable-arp-ping -p 22,445 Scan Complete...";;

                	[Nn]* ) echo "(OK) Skipping 2nd Discovery scan";;
                	* ) echo "(OK) Skipping 2nd Discovery scan";;
        	esac
fi



#Seems like this section not needed.. remove is so
#########Subsequent discovery scan ===================="

#        case $yn in
#                [Yy]* ) echo "============Phase 1.b - Nmap -Pn -n --top-ports=200 Scan ()=========="
#                echo "(OK) - About to run db_Nmap --top-ports=200 port scan to $DB database - (all Nmap scan output to $DB...)";
#                #echo "";;
#                /bin/cp $CONF/msf_default.rc $CONF/msf.rc;
#                echo "db_nmap -Pn -n --top-ports=200 $TODOHOSTSCOMMA" >> $CONF/msf.rc ;
#                echo "quit -y" >> $CONF/msf.rc;
#                $MSFBIN -r $CONF/msf.rc;;
#                [Nn]* ) echo "(OK) Skipping 2nd Discovery scan ";;
#                * ) echo "(OK) Skipping 2nd Discovery scan ";;
#        esac






echo "===========Phase 2 - NMAP --top-ports=200 Scan==========="
#MINOR Enhancement -- could exclude any hosts who's port 22,80,443 or 445 have a banner done previously  (to avoid duplicate scans)


#Careful here --> this SQL took a long time to get accurate!!! 
TODOHOSTS="$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT DISTINCT H1.address                              
FROM hosts H1
LEFT JOIN 
(SELECT DISTINCT H2.address from hosts H2, services S where S.port > 1 and S.port not in (22,80,443,445) and H2.id in (Select DISTINCT host_id from services where port > 1 and port not in (22,80,443,445)) AND S.host_id = H2.id) AS H2b
ON H1.address = H2b.address
WHERE H2b.address IS NULL AND H1.info IS NULL and H1.os_name like '%Unknown%'"""| grep -v row | grep -v address | grep -v """-""" )"

cd $CWD
if [ -z "$TODOHOSTS" ] ; then
	: #
else
#########NMAP Probing Top-200 tcp ports for known hosts============"
	#echo "$TODOHOSTS"
	for i in $TODOHOSTS; do TODOHOSTSCOMMA=`echo $TODOHOSTSCOMMA$i\ `; done
	#Removes trailing comma and add space between commas
	TODOHOSTSCOMMA=$(echo "$TODOHOSTSCOMMA" | sed '$s/.$//')
	TODOHOSTSCOMMA=$(echo "$TODOHOSTSCOMMA" | sed 's/,/, /g')
	read -p "(?) Do you want nmap to perform a nmap --top-ports=200 SYN scan ?(y/N)" yn

        case $yn in
		[Yy]* ) echo "============Nmap -Pn -n --top-ports=200 Scan ()=========="
                echo "(OK) - Starting db_Nmap --top-ports=200 port scan to $DB database - (all Nmap scan output to $DB...)";
		/bin/cp $CONF/msf_default.rc $CONF/msf.rc;
        	echo "db_nmap -Pn -n --top-ports=200 $TODOHOSTSCOMMA" >> $CONF/msf.rc ;
        	echo "quit -y" >> $CONF/msf.rc;
        	$MSFBIN -r $CONF/msf.rc;;
                [Nn]* ) echo "(OK) Skipping DB_Nmap --top-ports=200 ";;
                * ) echo "(OK) Skipping DB_Nmap --top-ports=200 ";;
        esac
fi
/usr/bin/python $CWD/tools/sniper.py db_update

######################################################################


########--- Nmap (-sV) Scan ()=========="
echo "===========Phase 3 - NMAP -sV (version) Scan ============"
ALLSVHOSTS="$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT DISTINCT H.address from hosts H, services S where S.proto = 'tcp' and S.info = '' and H.id in (Select host_id from services where info = '')  AND S.host_id = H.id and H.os_name = 'Unknown'""" | grep -v row | grep -v address | grep -v """-""" )"
cd $CWD

#echo "Hosts (with empty '' banner ports) that can be nmap -sV scanned.   note hosts with ' ' in banner have been scanned by sniper already: "
for i in $ALLSVHOSTS; do ALLSVHOSTSCOMMA=`echo $ALLSVHOSTSCOMMA$i\,`; done
ALLSVHOSTSCOMMA=$(echo "$ALLSVHOSTSCOMMA" | sed '$s/.$//')
#echo  "$ALLSVHOSTSCOMMA"

        read -p "(?) Do you want nmap to perform a (-sV) scan to get better banner info?(y/N)" yn

        case $yn in
		[Yy]* ) echo "============Nmap (-sV -T5 -n) Scan ()==========";
                	echo "(OK) - Starting db_Nmap -sV port scan to $DB database - (all Nmap scan output to $DB...)";
                	# Begin Outer Loop
                        for i in $ALLSVHOSTS
                        do  
                                DBNMAP=`echo `$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT DISTINCT S.port from hosts H, services S where H.address = '$i' and S.proto = 'tcp' and S.info = '' and H.id in (Select host_id from services where info = '')  AND S.host_id = H.id""" | grep -v row | grep -v port | grep -v """-""" )
                                DBNMAPCOMMA=''
                                #Begin Inner Loop
                                        for a in $DBNMAP
                                        do
                                                DBNMAPCOMMA=`echo $DBNMAPCOMMA$a\,`
                                        done
                                DBNMAPCOMMA=$(echo "$DBNMAPCOMMA" | sed '$s/.$//')
				/bin/cp $CONF/msf_default.rc $CONF/msf.rc
                		echo "db_nmap -sV -T5 --max-rtt-timeout 5000ms -n $i -p $DBNMAPCOMMA " >> $CONF/msf.rc
                		echo "quit -y" >> $CONF/msf.rc
                		$MSFBIN -r $CONF/msf.rc
				#Now that -sV is done, we may have some blank responses.. we find those and change blank to " " space so we don't rescan later on
				SVC=`echo `$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT host_id from services where host_id = (select id from hosts where address = '$i') and info = ''""" | grep -v row | grep -v host_id | grep -v """-""" )
				for b in $SVC
				  do
					SVCCOMMA=`echo $SVCCOMMA$b\,`
				  done
				SVCCOMMA=$(echo "$SVCCOMMA" | sed '$s/.$//')	
				/usr/bin/sudo -u postgres psql -d $DB -c """UPDATE services set info = ' ' where info = '' and host_id in ($SVCCOMMA)"""
				SVCCOMMA=""

                        done

                /usr/bin/python $CWD/tools/sniper.py db_update
                echo "(OK) - db_nmap -sV Scan Complete...";;


                [Nn]* ) echo "(OK) Skipping DB_Nmap -sV scan ";;
                * ) echo "(OK) Skipping DB_Nmap -sV scan ";;
        esac
###########--END Nmap -sV Scan ======
#===================================================




echo "==========Phase 4 General Metasploit (Aux) Scans ================"

##########################WINWMI auxiliary MSF a)smb_version, b)nbname(for hostname) and c)endpoint_mapper (for other hostname when nbname doesn't work)
        read -p "(?) Do you want MSF to definitively determine the Windows OS name/flavor or hostname?(y/N)" yn

        case $yn in
		[Yy]* ) echo "(OK) - Starting MSF auxiliary scan a)SMB Version b)nbname and c)endpoint_mapper Windows OS Probes==========";
			echo -n "(Optional) Specify the Windows Domain? (. for none)";
			read domain;
			echo -n "(Optional) Specify the Windows username?";
			read user;
			echo -n "(Optional) Specify the Windows password?";
			read pass;
                        /bin/cp $CONF/msf_default.rc $CONF/msf.rc;
                	echo "use auxiliary/scanner/smb/smb_version" >> $CONF/msf.rc;
			echo "services -p 445 -R" >> $CONF/msf.rc;
			echo "set SMBDomain = $domain" >> $CONF/msf.rc;
			echo "set SMBUser = $user" >> $CONF/msf.rc;
			echo "set SMBPass = $pass" >> $CONF/msf.rc;
			echo "run" >> $CONF/msf.rc;
			echo "use auxiliary/scanner/netbios/nbname" >> $CONF/msf.rc;
			echo "services -u -p 137 -R" >> $CONF/msf.rc;
			echo "run" >> $CONF/msf.rc;
			echo "use auxiliary/scanner/dcerpc/endpoint_mapper" >> $CONF/msf.rc;
			echo "services -p 135 -R" >> $CONF/msf.rc;
                        echo "run" >> $CONF/msf.rc;
                	echo "quit -y" >> $CONF/msf.rc;
                	$MSFBIN -r $CONF/msf.rc;;

 		[Nn]* ) echo "(OK) Skipping MSF Windows login";;
                * ) echo "(OK) Skipping MSF Windows login";;
	esac

#======================================================================
echo "==========*(TODO BROKEN)  Phase 4 General Nessus API  Scans ================"
#SERVICE='nessusd'
#if ps ax | grep -v grep | grep $SERVICE > /dev/null
#then
#    echo "(OK) - Found $SERVICE service running - skipping"
#else
#    echo "(OK) - Starting $SERVICE .... "
#    /etc/init.d/$SERVICE start
#    echo "(OK) - Starting $SERVICE service -- `ps ax | grep -v grep | grep $SERVICE`"
#fi
#SERVICE='nessusd'
#if ps ax | grep -v grep | grep $SERVICE > /dev/null
#then
#    echo "(OK) - Found $SERVICE service running - skipping"
#else
#    echo "(OK) - Starting $SERVICE .... "
#    /etc/init.d/$SERVICE start
#    echo "(OK) - Starting $SERVICE service -- `ps ax | grep -v grep | grep $SERVICE`"
#fi

#cd /tmp
	#UNIXSSH="$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT H.address from hosts H, services S where S.port = '22' and H.comments not like '%CRED%' and H.id = S.host_id""" | grep -v row | grep -v address | grep -v """-""" )"
	#cd $CWD
	#echo "SSH login(s) available to the following UNIX server(s)"
	#for i in $UNIXSSH; do UNIXSSHCOMMA=`echo $UNIXSSHCOMMA$i\,`; done
	#UNIXSSHCOMMA=$(echo "$UNIXSSHCOMMA" | sed '$s/.$//');

	#echo "$UNIXSSHCOMMA"
	#       read -p "(?) (BROKEN TODO - Do you want to provide NESSUS API with SSH credentials to definitively determine the OS name and flavor?(y/N)" yn
	#       case $yn in
	#               [Yy]* ) echo "==========Phase 2.a Starting - UNIX(SSH) OS Probes==========";
	#               /opt/nessus/bin/nessuscmd --remote localhost --remote-port 1241 --login service --password service -V -p 22 -i 11936 $UNIXSSHCOMMA --sshi > $CWD/tmp/unix_os_sp.txt;
	#               /bin/cat $CWD/tmp/unix_os_sp.txt | grep "Confidence Level : 100" -B 40 -A 2 | grep -e "Results found" -e "Remote operating system" -A 1 | grep -v "Host information" | grep -v "\-\-" | sed -e 's/\+ Results found on //' | grep -v Confidence  | sed 's/^[ \t]*//' | sed -e :a -e '$!N;s/\n|//;ta' -e 'P;D' | cut -d ":" -f1,3 | awk 'BEGIN {FS=OFS=":"} {temp=$1; $1=$2; $2=temp} {print}'| sed 's/^[ \t]*//;s/[ \t]*$//' | sed -e "s/^/UPDATE hosts SET info = '/" | sed -e "s/\:/', comments = 'OS-Updated-by-sniper.py_CRED' where address = '/" | sed "s/$/';/" > /tmp/unix_os_sp.SQL.txt;
	#               cd /tmp;
	#               /usr/bin/sudo -u postgres psql -d $DB -f /tmp/unix_os_sp.SQL.txt >> $LOG/nessuscmd.log 2>&1;
	#               /bin/cat /tmp/unix_os_sp.SQL.txt >> $LOG/nessuscmd.log 2>&1;

	#Can set next line to only show up in DEBUG level
	#               echo "Successful SSH Logins here (OS Updated) --"; /bin/cat /tmp/unix_os_sp.SQL.txt;

	#Cleanup
	#               rm /tmp/unix_os_sp*;
	#               cd $CWD;
	#               rm $CWD/tmp/unix_os_sp*;;
	#               [Nn]* ) echo "(OK) Skipping SSH login";;
	#               * ) echo "(OK) Skipping SSH login";;
	#       esac



	#################BEGIN BETA - General Nessus################
	#echo "============**BETA**==Phase 3 - General Nessus=========="
	#ALLNOWINHOSTS="$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT H.address from hosts H where H.os_name not like ('%indows%') """ | grep -v row | grep -v address | grep -v """-""" )"
	#cd $CWD
	#echo "All Non-WIN Hosts to be scanned with Nessus: "
	#for i in $ALLNOWINHOSTS; do ALLNOWINHOSTSCOMMA=`echo $ALLNOWINHOSTSCOMMA$i\,`; done
	#ALLNOWINHOSTSCOMMA=$(echo "$ALLNOWINHOSTSCOMMA" | sed '$s/.$//')
	#echo  "$ALLNOWINHOSTSCOMMA"
	#cp $CWD/tools/sniper.rb /opt/backbox/msf/plugins
	#        read -p "(?)**BETA** Do you want nessus to perform a non-Windows plugin scan (creds)?(y/N)" yn
	#        case $yn in
	#                [Yy]* ) echo "============Phase 3.a - Nessus Scan (NON-WINDOWS) (cred if supplied in policy)==========";
	#                /bin/cp /home/sat/.msf4/msfconsole.rc $CONF/msf.rc;
	#                echo "(OK) - About to run Nessus port scan to $DB database - (all Nessus scan output to $DB...)";
	#                echo "load nessus" >> $CONF/msf.rc ;
	#                echo "nessus_connect service:service@localhost:8834 ok" >> $CONF/msf.rc ;
	#                @#$@#$DO THIS INSTEAD!!!!  nessus_db_scan -h
	#                echo "nessus_scan_new -1 \"Phase 2 non-Win - Plugin scan w creds\" $ALLNOWINHOSTSCOMMA" >> $CONF/msf.rc;
	#                echo "load sniper" >> $CONF/msf.rc;
	#                echo "MSF ERROR type quit to continue- here's where we probably have to write our own ruby to know know when job is done , import and quit msf" >> $CONF/msf.rc;
	#                $MSFBIN -r $CWD/conf/msf.rc ;
	#                echo "(OK) - Nessus non-WIN plugin Scan Complete...";;
	#
	#                [Nn]* ) echo "(OK) Skipping Nessus plugin scan ";;
	#                * ) echo "(OK) Skipping Nessus plugin scan";;
	#        esac
	#
	###########Nessus WIN Scan section#############3
	#ALLWINHOSTS="$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT H.address from hosts H where H.os_name like ('%indows%') """ | grep -v row | grep -v address | grep -v """-""" )"
	#cd $CWD
	#echo "All WIN Hosts to be Port scanned: "
	#for i in $ALLWINHOSTS; do ALLWINHOSTSCOMMA=`echo $ALLWINHOSTSCOMMA$i\,`; done
	#ALLWINHOSTSCOMMA=$(echo "$ALLWINHOSTSCOMMA" | sed '$s/.$//')
	#echo "$ALLWINHOSTSCOMMA"
	#cp /home/sat/.msf4/msfconsole.rc $CONF/msf.rc
	#cp $CWD/tools/sniper.rb /opt/backbox/msf/plugins
	#        read -p "(?) Do you want nessus to perform a Windows plugin scan (creds)?(y/N)" yn
	#
	#        case $yn in
	#                [Yy]* ) echo "============Phase 3.b - Nessus Scan (WINDOWS) (cred if supplied in policy)==========";
	#               /bin/cp /home/sat/.msf4/msfconsole.rc $CONF/msf.rc;
	#                echo "(OK) - About to run Nessus port scan to $DB database - (all Nessus scan output to $DB...)";
	#                echo "load nessus" >> $CONF/msf.rc ;
	#                echo "nessus_connect service:service@localhost:8834 ok" >> $CONF/msf.rc ;
	#                echo "nessus_scan_new -1 \"Phase 2 Win - Plugin scan w creds\" $ALLWINHOSTSCOMMA" >> $CONF/msf.rc;
	#                echo "load sniper" >> $CONF/msf.rc;
	#                echo "MSF ERROR type quit to continue- here's where we probably have to write our own ruby to know know when job is done , import and quit msf" >> $CONF/msf.rc;
	#                $MSFBIN -r $CWD/conf/msf.rc ;
	#                echo "(OK) - Nessus WIN plugin Scan Complete...";;
	#
	#                [Nn]* ) echo "(OK) Skipping Nessus plugin scan ";;
	#                * ) echo "(OK) Skipping Nessus plugin scan ";;
	#        esac
	#
	###########################END NESSUS BETA STUFF########################3


	###################WINWMI NESSUSCMD
	#WINWMI="$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT DISTINCT H.address from hosts H, services S where S.port = '445' and H.comments not like '%CRED%' and H.id = S.host_id""" | grep -v row | grep -v address | grep -v """-""" )"
	#cd $CWD
	#echo "WMI login(s) available to the following WINDOWS device(s)"
	#for i in $WINWMI; do WINWMICOMMA=`echo $WINWMICOMMA$i\,`; done
	#WINWMICOMMA=$(echo "$WINWMICOMMA" | sed '$s/.$//');

	#echo "$WINWMICOMMA"
	#        read -p "(?) BROKEN - TODO - Do you want to provide NESSUS API with WINDOWS credentials to definitively determine the OS name and flavor?(y/N)" yn
	#
	#        case $yn in
	#                [Yy]* ) echo "==========Phase 2.b Starting - WINDOWS(WMI) OS Probes==========";
	#                        /opt/nessus/bin/nessuscmd --remote localhost --remote-port 1241 --login service --password service -V -p 445 -i 11936 $WINWMICOMMA --smbi > $CWD/tmp/win_os_sp.txt;
	#/bin/cat $CWD/tmp/win_os_sp.txt | grep "Confidence Level : 100" -B 40 -A 2 | grep -e "Results found" -e "Remote operating system" -A 1 | grep -v "Host information" | grep -v "\-\-" | sed -e 's/\+ Results found on //' | grep -v Confidence  | sed 's/^[ \t]*//' | sed -e :a -e '$!N;s/\n|//;ta' -e 'P;D' | cut -d ":" -f1,3 | awk 'BEGIN {FS=OFS=":"} {temp=$1; $1=$2; $2=temp} {print}'| sed 's/^[ \t]*//;s/[ \t]*$//' | sed -e "s/^/UPDATE hosts SET info = '/" | sed -e "s/\:/', comments = 'OS-Updated-by-sniper.py_CRED' where address = '/" | sed "s/$/';/" > /tmp/win_os_sp.SQL.txt;
	#cd /tmp;
	#/usr/bin/sudo -u postgres psql -d $DB -f /tmp/win_os_sp.SQL.txt >> $LOG/nessuscmd.log 2>&1;
	#/bin/cat /tmp/win_os_sp.SQL.txt >> $LOG/nessuscmd.log 2>&1;

	#Can set next line to only show up in DEBUG level
	#echo "OS Updates here--"; /bin/cat /tmp/win_os_sp.SQL.txt;

	#Cleanup
	#rm /tmp/win_os_sp*;
	#cd $CWD;
	#rm $CWD/tmp/win_os_sp*;;
	#                [Nn]* ) echo "(OK) Skipping Nessuscmd Windows login";;
	#                * ) echo "(OK) Skipping Nessuscmd Windows login";;
	#        esac

#=============================

echo "==========*(TODO BROKEN)  Phase 5 MAGIC CVE report ================"
	#echo "============MSF/CVE Magic thing?============="

	#read -p "(?) Do you want SNIPER to run the MAGIC CVE thing?(y/N)" yn

	#case $yn in
	#       [Yy]* ) /usr/bin/python $CWD/tools/sniper.py cve_update;;
	#       [Nn]* ) echo "(OK) Skipping MAGIC CVE report";;
	#       * ) echo "(OK) Skipping MAGIC CVE report";;
	#esac

	#This is used to generate the MSF/Nessus CVE listing

	#if ls $CWD/tmp/nessus.cve.msf.txt &> /dev/null; then
	#        echo "(OK) - Nessus/MSF CVE mapping Found"
	#else
	#        echo "(OK) - GENERATING new Nessus/MSF CVE mapping - This may take a few minutes!!"
	#        cd /opt/nessus/lib/nessus/plugins;
	#        grep -f $CWD/conf/msf_whitelist1.txt *.nasl | cut -d ":" -f1 | \
	    #        uniq | xargs grep -f $CWD/conf/msf_whitelist.txt | \
	    #        grep -v -i -f $CWD/conf/msf_blacklist.txt | \
	    #        #################
	#        #BUGSPLAT!!- Nessus .nasl are inconsistant - see difference between smb_nt_ms10-002.nasl & smb_nt_ms13-090.nasl
	#They put a carriage return after the cve# in one and not in the other.. so, this make this cut/sed/awk not work
	#in those cases..  suggestion to just do this in python which maybe could handle dirty data regex a bit easier.
	#################
	#FUTURE CONSIDERATION - (msf>search cve:#####)
	#Change B1 to B2 to get the CVE-XXX part
	#        grep -B2 "metasploit_name" | \
	    #Cleanup Data formating (1st row = NSSID, 2nd= CVE****, 3rd=MSF name)
	#        cut -d """(""" -f2 | cut -d """:""" -f3 | cut -d """)""" -f1 | cut -d """'""" -f2 | cut -d """'""" -f1 | grep -v """\-\-""" | \
	    #Only take the NSS and CVE lines
	#        grep -e '^[0-9][0-9][0-9][0-9][0-9]\|CVE' | \
	    #Combine NSS + CVE lines
	#        sed ':a;$!N;s/\n\"CVE/\:"CVE/;ta;P;D' | \
	    #Remove NSS with no CVE listed
	#        grep CVE | uniq | sort > $CWD/tmp/nessus.cve.msf.txt
	#        cd $CWD
	#fi
	#######

	#################BEGIN BETA NESSUSCMD/MSF####################
	#read -p "(**BETA**) Generate NESSUSCMD/Metasploit Correlated (SSH) Scan?(y/N)" yn
	#       case $yn in
	#               [Yy]* ) NSSMSF="$(cd /opt/nessus/lib/nessus/plugins; /bin/grep -f $CWD/conf/msf_whitelist1.txt *.nasl | cut -d """:""" -f1 | uniq | xargs grep -f $CWD/conf/msf_whitelist.txt | grep -v -i -f $CWD/conf/msf_blacklist.txt | grep -B1 """metasploit_name""" | cut -d """(""" -f2 | cut -d """:""" -f3 | cut -d """)""" -f1 | cut -d """'""" -f2 | cut -d """'""" -f1 | grep -v """\-\-"""| grep -e ^[0-9][0-9][0-9][0-9][0-9])";
	#                       for i in $NSSMSF; do NSSMSFCOMMA=`echo $NSSMSFCOMMA$i\,`; done;
	#                       NSSMSFCOMMA=$(echo "$NSSMSFCOMMA" | sed '$s/.$//');
	#                       /opt/nessus/bin/nessuscmd --remote localhost --remote-port 1241 --login service --password service -V -p 22 -i $NSSMSFCOMMA $UNIXSSH --sshi > $CWD/results/nss-msf-unix.txt;;
	#
	#Cleanup
	#
	#               [Nn]* ) echo "(OK) Skipping SSH login";;
	#                * ) echo "(OK) Skipping SSH login";;
	#
	#        esac
	#
	#echo "(**BETA**) NESSUSCMD/Metasploit Correlations Found (UNIX)- see ./results/nss-msf-unix.txt"
	#grep "Results found on" $CWD/results/nss-msf-unix.txt
	#
	#
	#############END BETA NESSUSCMD/MSF########################



	#################BEGIN BETA NESSUS API MSF ######################
	#read -p "(**BETA**) Generate API Metasploit Correlated (WMI) Scan?(y/N)" yn
	#        case $yn in
	#                [Yy]* ) NSSMSF="$(cd /opt/nessus/lib/nessus/plugins; /bin/grep -f $CWD/conf/msf_whitelist1.txt *.nasl | cut -d """:""" -f1 | uniq | xargs grep -f $CWD/conf/msf_whitelist.txt | grep -v -i -f $CWD/conf/msf_blacklist.txt | grep -B1 """metasploit_name""" | cut -d """(""" -f2 | cut -d """:""" -f3 | cut -d """)""" -f1 | cut -d """'""" -f2 | cut -d """'""" -f1 | grep -v """\-\-"""| grep -e ^[0-9][0-9][0-9][0-9][0-9])";
	#                        for i in $NSSMSF; do NSSMSFCOMMA=`echo $NSSMSFCOMMA$i\,`; done;
	#                        NSSMSFCOMMA=$(echo "$NSSMSFCOMMA" | sed '$s/.$//');
	#                       /opt/nessus/bin/nessuscmd --remote localhost --remote-port 1241 --login service --password service -V -p 22 -i $NSSMSFCOMMA $WINWMICOMMA --smbi > $CWD/results/nss-msf-win.txt;;
	#
	#Cleanup
	#                [Nn]* ) echo "(OK) Skipping WMI login";;
	#                * ) echo "(OK) Skipping WMI login";;
	#        esac
	#
	#echo "**BETA** - NESSUS API/ Metasploit Correlations (WINDOWS)- see ./results/nss-msf-win.txt"
	#grep "Results found on" $CWD/results/nss-msf-win.txt
	#################END BETA NESSUS MSF##########################




echo "==========Phase 6 eyewitness web thumbnail Scans ================"
#eyewitness#####
read -p "(?) Do you want to thumbnail ports (80,443,8000,8080,8443) with 'eyewitness' ?(y/N)" yn

case $yn in
	[Yy]* ) echo "(OK) Starting - eyewitness scan=========="
	    /bin/cp $CONF/msf_default.rc $CONF/msf.rc;
	    echo "services -p 80,443,8000,8080,8443 -o /tmp/sniper.eyewitness.txt" >> $CONF/msf.rc ;
	    echo "quit -y" >> $CONF/msf.rc;
	    $MSFBIN -r $CONF/msf.rc;
	    cut -d "\"" -f2 /tmp/sniper.eyewitness.txt > /tmp/sniper.eyewitness.b.txt;
	    rm /tmp/sniper.eyewitness.txt;
	    awk '{if (NR!=1) {print}}' /tmp/sniper.eyewitness.b.txt > /tmp/sniper.eyewitness.c.txt;
	    $EYEWITNESS --no-prompt --prepend-https -f /tmp/sniper.eyewitness.c.txt --web -d sniper;
	    rm /tmp/sniper.eyewitness.b.txt;
	    rm /tmp/sniper.eyewitness.c.txt;
	    cp -R /usr/share/eyewitness/sniper /var/www/html/sniper;
	    echo "(OK) eyewitness scan complete - see /var/www/html/sniper for results";;

    [Nn]* ) echo "(OK) Skipping eyewitness ";;
    * ) echo "(OK) Skipping eyewitness ";;
esac
##################################################
	

echo "=============Report====================="
read -p "(?) Do you want SNIPER to run the sniper report?(Y/n)" yn

case $yn in
	[Yy]* ) /usr/bin/python $CWD/tools/sniper.py;;
	[Nn]* ) echo "(OK) Skipping sniper report";;
	* ) /usr/bin/python $CWD/tools/sniper.py;;
esac
 
echo "(OK) SNIPER COMPLETE"


