# sniper

## About
sniper is a command line host discovery tool used to scan large networks

## Installation
```
git clone https://github.com/mvdevnull/sniper
cd sniper
chmod +x ./sniper
./sniper.sh
```

## Dependancies
### Required
* python 			----> apt-get install python
* psql python module 	----> apt-get install python-psycopg2
### Optional
* eyewitness 		----> apt-get install eyewitness   
* nessus ----> https://www.tenable.com/downloads/nessus 


## Core Features
### Scanning
* db_nmap (all nmap results located in MSF database)
* metasploit discovery (auxiliary results located in MSF database)
* eyewitness web thumbnails (located in /var/www/html/sniper)
### Data Updates
* OS name/flavor/SP confirmation 
### Reporting
* insecure protocols
* gaping holes

## Future Features TBC
* nessus API (standard , gaping holes and compliance)
* openscap scanning
