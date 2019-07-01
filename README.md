# sniper

## About
sniper is a command line host discovery tool used to scan large networks

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

## Installation
### Core Application
```
git clone https://github.com/mvdevnull/sniper.git
chmod +x ./sniper/sniper.sh

```
### Dependancies
````
apt-get install python  #Install python 2.x
apt-get install python-psycopg2  #Install postgresql python module
apt-get install eyewitness   #Install eyewitness
````
## Usage
```
cd sniper
./sniper.sh   #answer questions and wait for scans
msfconsole #run in separate window and wait for new hosts
```

## Future Features (TBD)
* nessus API (standard , gaping holes and compliance)
* openscap scanning
