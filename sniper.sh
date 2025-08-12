#!/usr/bin/env bash

#Author - chrisdhebert@gmail.com
#Version - 2.2025-08-08

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

clear

CWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
MSFBIN="/usr/bin/msfconsole -q"
EYEWITNESS="/usr/bin/eyewitness"
DB='msf'

SERVICE='postgresql'
if ps ax | grep -v grep | grep $SERVICE > /dev/null
then
        echo "(OK) - Found $SERVICE service running"
else
        echo "(OK) - Starting $SERVICE .... "
        /etc/init.d/$SERVICE start
        echo "(OK) - Starting $SERVICE service "
fi

if test -f "$EYEWITNESS"; then
    echo "(OK) - Found $EYEWITNESS "
else
    echo "(ERROR) - eyewitness not found - install eyewitness (ex: apt-get install eyewitness)"
    exit
fi

echo '  _________      .__                     ' 
echo ' /   _____/ ____ |__|_____   ___________ '
echo ' \_____  \ /    \|  \____ \_/ __ \_  __ \'
echo ' /        \   |  \  |  |_> >  ___/|  | \/'
echo '/_______  /___|  /__|   __/ \___  >__|   '
echo '        \/     \/   |__|        \/       '


#Copying all known Nmap 
nmapRESULTS=$CWD/nmap
nessusRESULTS=$CWD/nessus
CONF=$CWD/conf

#this is needed only if we call msfconsole as opposed to nc to msfd on localhost: 55554
cp $CONF/msf_default.rc $CONF/msf.rc



#Here is where we make msfd a "tiny" bit faster...by
##Getting rid of all metasploit banners!!!!
echo /usr/share/metasploit-framework/data/logos/*.txt | xargs -n1 cp /dev/null


#Only import files if we have new ones

if ls $nmapRESULTS/new/*.xml &> /dev/null; then
		echo "(OK) - Importing only newer NMAP to $DB database - (all Nmap output in ./nmap/new directory to $DB...)"
		/bin/cp $CONF/msf_default.rc $CONF/msf.rc
		echo "db_import $nmapRESULTS/new/*.xml" >> $CONF/msf.rc
		echo "quit -y" >> $CONF/msf.rc
		$MSFBIN -r $CONF/msf.rc
		mv $nmapRESULTS/new/*.xml $nmapRESULTS/import_complete
		echo "(OK) - NMAP - DB Import Complete..."
		/usr/bin/python3 $CWD/tools/sniper.py db_update
else
		echo "(OK) - No new nmap files found in ./nmap/new directory to import"
fi

if ls $nessusRESULTS/new/*.nessus &> /dev/null; then
		echo "(OK) - Importing only newer Nessus to $DB database - (all Nessus output in ./nessus/new directory to $DB...)"
		/bin/cp $CONF/msf_default.rc $CONF/msf.rc
		echo "db_import $nessusRESULTS/new/*.nessus" >> $CONF/msf.rc
		echo "quit -y" >> $CONF/msf.rc
		$MSFBIN -r $CONF/msf.rc
		mv $nessusRESULTS/new/*.nessus $nessusRESULTS/import_complete
		echo "(OK) - Nessus - DB Import Complete..."
		/usr/bin/python3 $CWD/tools/sniper.py db_update
else
		echo "(OK) - No new Nessus files found in ./nessus/new directory to import"
fi

############################################
#Required so that postgres user has access to $CWD change after command
TOTALHOSTS=0
cd /tmp
TOTALHOSTS="$(/usr/bin/sudo -u postgres psql -d $DB -c """Select count(*) from hosts;""" | grep row -B 1| grep -v row)"
cd $CWD

#####Do a Quick & efficient NMAP discovery##########
echo "============Phase 1 Nmap Discovery Scan ============"

if [ $TOTALHOSTS -eq "0" ] ; then
	echo "(OK) You have *NO* hosts in the database $DB. Enter the IP Range for QUICK host discovery? [Nmap compatible example - 192.168.1.1-200]"
    	read IPRANGE
	echo "(OK) Starting Nmap Discovery Scan..."
	/bin/cp $CONF/msf_default.rc $CONF/msf.rc
        echo "db_nmap -Pn -v --disable-arp-ping -p 22,80,443,445 $IPRANGE --open" >> $CONF/msf.rc
        echo "quit -y" >> $CONF/msf.rc
        $MSFBIN -r $CONF/msf.rc

	#We do this to remove filtered ports
        /usr/bin/python3 $CWD/tools/sniper.py db_update
	echo "(OK) Completed Nmap Discovery Scan"

else
	echo "(OK) $TOTALHOSTS Total hosts in database $DB."
	read -p "(?) Do you want nmap to perform a 2nd discovery scan?(y/N)" yn

		case $yn in
                	[Yy]* ) echo "Enter the IP Range for QUICK host discovery? [Nmap compatible example - 192.168.1.1-200]";
                	read IPRANGE;
			echo "(OK) Starting Nmap (2nd) Discovery scan... ";
        		/bin/cp $CONF/msf_default.rc $CONF/msf.rc;
        		echo "db_nmap -Pn -v --disable-arp-ping -p 22,80,443,445 $IPRANGE " >> $CONF/msf.rc;
        		echo "quit -y" >> $CONF/msf.rc;
        		$MSFBIN -r $CONF/msf.rc;

			#We do this to remove filtered ports
        		/usr/bin/python3 $CWD/tools/sniper.py db_update;
        		echo "(OK) Completed Discovery Scan";;

                	[Nn]* ) echo "(OK) Skipping Nmap (2nd) Discovery scan";;
                	* ) echo "(OK) Skipping Nmap (2nd) Discovery scan";;
        	esac
fi




echo "===========Phase 2 - NMAP top### Port Scan==========="

#Careful here --> this SQL took a long time to get accurate!!! 
TODOHOSTS="$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT DISTINCT H1.address                              
FROM hosts H1
LEFT JOIN 
(SELECT DISTINCT H2.address from hosts H2, services S where S.port > 1 and S.port not in (22,80,443,445) and H2.id in (Select DISTINCT host_id from services where port > 1 and port not in (22,80,443,445)) AND S.host_id = H2.id) AS H2b
ON H1.address = H2b.address
WHERE H2b.address IS NULL AND H1.info IS NULL and H1.os_name like '%Unknown%'"""| grep -v row | grep -v address | grep -v """-""" )"

cd $CWD
if [ -z "$TODOHOSTS" ] ; then
	echo "(OK) Skipping Nmap top200 Port Scan - No appropriate hosts";
else
#########NMAP Probing Top-### tcp ports for known hosts============"
	#echo "$TODOHOSTS"
	for i in $TODOHOSTS; do TODOHOSTSCOMMA=`echo $TODOHOSTSCOMMA$i\ `; done
	#Removes trailing comma and add space between commas
	TODOHOSTSCOMMA=$(echo "$TODOHOSTSCOMMA" | sed '$s/.$//')
	TODOHOSTSCOMMA=$(echo "$TODOHOSTSCOMMA" | sed 's/,/, /g')
	read -p "(?) Do you want nmap to perform a nmap --top-ports=### scan ?(y/N)" yn	
 	read -p "(?) How many tcp ports to scan (1-65535) (default=200) ?(###/200)" numports
	if [ -z "$numports" ] ; then
 		numports=200
   	else
    		echo "Number of Ports chosen="$numports
	fi
        case $yn in
		[Yy]* ) echo "(OK) - Starting Nmap top "$numports" Port Scan ...";
		/bin/cp $CONF/msf_default.rc $CONF/msf.rc;
  		#Adjustable way to increase timeouts to a function of "$numports".  (X/10)+50
		timeout=$(awk "BEGIN {print int((($numports / 10) + 50) + 0.5)}")
        echo "db_nmap --top-ports="$numports" -Pn -v -n --disable-arp-ping --max-rtt-timeout 1500ms --version-intensity 2 --host-timeout 200s --script-timeout 50s --save -oG ./nmap/top-"$numports"ports-"`date +"%Y-%m-%d"`.gnmap" -oN ./nmap/top-"$numports"ports-"`date +"%Y-%m-%d"`.nmap";
        echo "mv ~/.msf4/local/*.xml ./nmap/top-"$numports"ports-"`date +"%Y-%m-%d"`.xml"" >> $CONF/msf.rc;
	 	#Considering adding a udp scan, but problem is it's open/filtered and get's deleted later on.  reason is, aux scan needes port 137 .
   		#echo "db_nmap -sU -p 137,161 -Pn -v -n --disable-arp-ping --max-rtt-timeout 1500ms --host-timeout 30s $TODOHOSTSCOMMA" >> $CONF/msf.rc ;
    	echo "quit -y" >> $CONF/msf.rc;
		$MSFBIN -r $CONF/msf.rc;;
		[Nn]* ) echo "(OK) Skipping Nmap top"$numports" Port Scan";;
		* ) echo "(OK) Skipping Nmap top"$numports" Port Scan";;
        esac
fi
/usr/bin/python3 $CWD/tools/sniper.py db_update

######################################################################



echo "==========Phase 3 General Metasploit (Aux) Scans ================"
#WINWMI auxiliary MSF a)smb_version, b)nbname(for hostname) and c)endpoint_mapper (for other hostname when nbname doesn't work)
TODOHOSTS=""
TODOHOSTS="$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT DISTINCT host_id from services where 
port in (139,137,445) and info = '' """| grep -v row | grep -v host_id | grep -v """-""" )"
cd $CWD
if [ -z "$TODOHOSTS" ] ; then
	echo "(OK) Skipping Metasploit (Aux) Scan - No appropriate hosts";
else

	read -p "(?) Do you want MSF to determine the Windows OS name/flavor or hostname?(y/N)" yn

        case $yn in
		[Yy]* ) echo "(OK) - Starting MSF auxiliary scan a)SMB Version b)nbname OS Probes... ";
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
   			#RPC mapper seemed to muddy waters give too many ports that were more internal than external
			#echo "use auxiliary/scanner/dcerpc/endpoint_mapper" >> $CONF/msf.rc;
			#echo "services -p 135 -R" >> $CONF/msf.rc;
                        #echo "run" >> $CONF/msf.rc;
                	echo "quit -y" >> $CONF/msf.rc;
                	$MSFBIN -r $CONF/msf.rc;;

 		[Nn]* ) echo "(OK) Skipping MSF Windows Scan";;
                * ) echo "(OK) Skipping MSF Windows Scan";;
	esac
fi
######################################################################


echo "===========Phase 4 - NMAP Version (-sV) Scan ============"
ALLSVHOSTS="$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT DISTINCT H.address from hosts H, services S where S.proto = 'tcp' and S.info = '' and H.id in (Select host_id from services where info = '')  AND S.host_id = H.id """ | grep -v row | grep -v address | grep -v """-""" )"
cd $CWD

#echo "Hosts (with empty '' banner ports) that can be nmap -sV scanned.   note hosts with ' ' in banner have been scanned by sniper already: "
for i in $ALLSVHOSTS; do ALLSVHOSTSCOMMA=`echo $ALLSVHOSTSCOMMA$i\,`; done
ALLSVHOSTSCOMMA=$(echo "$ALLSVHOSTSCOMMA" | sed '$s/.$//')

if [ -z "$ALLSVHOSTSCOMMA" ] ; then
	echo "(OK) Skipping Nmap Version Scan - No appropriate hosts";
else
        read -p "(?) Do you want nmap to perform a (-sV) scan to get detailed banner info?(y/N)" yn

        case $yn in
                [Yy]* ) echo "============Nmap Version (-sV) Scan ==========";
                        echo "(OK) - Starting Nmap Version Scan...";
                        # Begin Outer Loop
                        for i in $ALLSVHOSTS
                        do
                                DBNMAP=`echo `$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT DISTINCT S.port from hosts H, services S where H.address = '$i' and S.proto = 'tcp' and S.info = '' and H.id in (Select host_id from services where info = '')  AND S.host_id = H.id""" | grep -v row | grep -v port | grep -v """-""" )
                                DBNMAPCOMMA=''
                                HOSTID=''
								/bin/cp $CONF/msf_default.rc $CONF/msf.rc
                                #Begin Inner Loop
                                        for a in $DBNMAP
                                        do
                                            DBNMAPCOMMA=`echo $DBNMAPCOMMA$a\,`
											echo "db_nmap -sV -Pn -n -T5 --disable-arp-ping --max-rtt-timeout 300ms --version-intensity 6 --host-timeout 11s --script-timeout 10s $i -p $a " >> $CONF/msf.rc
                                        done
								echo "quit -y" >> $CONF/msf.rc
								#We don't scan all ports for 1 host, because if 1 port timesout, no ports are recorded!!  So, we loop scans 1 port per host above
								#DBNMAPCOMMA=$(echo "$DBNMAPCOMMA" | sed '$s/.$//')
                                #/bin/cp $CONF/msf_default.rc $CONF/msf.rc
                                #echo "db_nmap -sV -Pn -v -n -T5 --disable-arp-ping --max-rtt-timeout 300ms --version-intensity 6 --host-timeout 30s --script-timeout 10s $i -p $DBNMAPCOMMA " >> $CONF/msf.rc
                                #echo "quit -y" >> $CONF/msf.rc
                                $MSFBIN -r $CONF/msf.rc
                                #Now that -sV is done, we may have some blank responses.. we find those and change blank to " " space so we don't rescan later on
                                HOSTID=`echo `$(/usr/bin/sudo -u postgres psql -d $DB -c """select id from hosts where address = '$i'""" | grep -v row | grep -v id | grep -v """-""" )
								sVdone=`echo `$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT count(*) from services where proto = 'tcp' and info = ' '"""  | grep -v row | grep -v count | grep -v """-""" )
								sVtodo=`echo `$(/usr/bin/sudo -u postgres psql -d $DB -c """SELECT count(*) from services where proto = 'tcp' and info = ''"""  | grep -v row | grep -v count | grep -v """-""" )
								sVcomplete=`echo `$(python -c "print(round($sVdone / ($sVdone + $sVtodo)*100,2) )" )
                                echo "(OK) - Version -SV Scan - "$sVcomplete"% complete."
				echo "(OK) - the following number of blank service banners will not be scanned again. "
                                /usr/bin/sudo -u postgres psql -d $DB -c """UPDATE services set info = ' ' where info = '' and host_id = $HOSTID and port in ($DBNMAPCOMMA)"""
                        done

                /usr/bin/python3 $CWD/tools/sniper.py db_update
                echo "(OK) - Nmap Version Scan Complete...";;


                [Nn]* ) echo "(OK) Skipping DB_Nmap -sV scan ";;
                * ) echo "(OK) Skipping Nmap Version scan ";;
        esac
fi
######################################################################


echo "==========Phase 5 Eyewitness Web Thumbnail Scans ================"
read -p "(?) Do you want to create thumbnails on ports (80,443,8000,8080,8443) with 'eyewitness' ?(y/N)" yn

case $yn in
	[Yy]* ) echo "(OK) Starting - Eyewitness Scan..."
                if test -f "./eyewitness/ew.db"; then 
	 		echo "(OK) - Found unfinished scan - resuming.. "
			/usr/bin/sudo -u postgres $EYEWITNESS --resume ./eyewitness/ew.db    			
		else
			/bin/cp $CONF/msf_default.rc /tmp/sniper-eye.msf.rc
			echo "services -p 80,443,8000,8080,8443 -u -o /tmp/sniper.eyewitness.txt"  >> /tmp/sniper-eye.msf.rc
			echo "quit -y" >> /tmp/sniper-eye.msf.rc
			$MSFBIN -r /tmp/sniper-eye.msf.rc
			rm /tmp/sniper-eye.msf.rc
			tail -n +2 /tmp/sniper.eyewitness.txt | cut -d "\"" -f2-4 | grep -v address | sed 's/\",\"/\:/g' > /tmp/sniper.eyewitness.b.txt
			rm /tmp/sniper.eyewitness.txt
			chmod o+w .
	  		/usr/bin/sudo -u postgres $EYEWITNESS -f /tmp/sniper.eyewitness.b.txt --no-prompt --max-retries 0 --web --timeout 5 --threads 20 -d eyewitness
     			rm /tmp/sniper.eyewitness.b.txt
       		fi
		echo "(OK) Eyewitness scan complete - see ./eyewitness/report.html";;
    [Nn]* ) echo "(OK) Skipping Eyewitness Scan";;
    * ) echo "(OK) Skipping Eyewitness Scan";;
esac
##################################################
	

echo "=============Report====================="
read -p "(?) Do you want SNIPER to run the sniper report?(Y/n)" yn

case $yn in
	[Yy]* ) /usr/bin/python3 $CWD/tools/sniper.py;;
	[Nn]* ) echo "(OK) Skipping sniper report";;
	* ) /usr/bin/python3 $CWD/tools/sniper.py;;
esac
 
echo "(OK) SNIPER COMPLETE"


