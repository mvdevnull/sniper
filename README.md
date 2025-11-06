# sniper

## About
sniper is a command line host discovery tool used to scan large networks.  
sniper saves time by efficiently scanning in a strategic order: 
* 1)Discovering only alive hosts in large ranges
* 2)TCP ports for only alive hosts
* 3)Deep -sV banner scans for only open tcp ports and will not repeat -sV for queries with no response
* 4)Runs eyewitness for web frontends

### Core Features
###### Scanning
* db_nmap (all nmap results centralized in Metasploit database)
* metasploit discovery (auxiliary results centralized in Metasploit database)
* eyewitness web thumbnails (centralized in eyewitness/report.html)
* Service banner details via nmap
* Nmap & Nessus import integration
###### Custom OS Detection
* OS name confirmation via custom nmap rules
* OS name confirmation via custom eyewitness source rules
###### Reporting
* Insecure protocols via nmap
* Unpatched/Outdated Services via nmap
* Common findings via Nessus pluginID
* Gaping holes via Nessus pluginID

### Installation
```
git clone https://github.com/mvdevnull/sniper.git
cd sniper
sudo msfdb init                                        #Initialize postgres for MSF
```
###### Dependencies
````
sudo apt-get install metasploit-framework              #Install metasploit framework
sudo apt-get install python3                           #Install python3
sudo apt-get install python3-psycopg2                  #Install postgresql python3 library
sudo apt-get install eyewitness                        #Install eyewitness
sudo apt-get install gowitness                         #Install gowitness
sudo apt-get install sqlite3                           #Install sqlite3
sudo apt-get install dirb                              #Install dirb
````
### Usage
```
sudo bash ./sniper.sh                             #answer questions and wait for scans
msfconsole                                        #run in separate window and wait for new hosts
```

### Future Features (TBD)
* Other bugs and potential features are noted in the [/docs/todo.txt](https://github.com/mvdevnull/sniper/blob/master/docs/todo.txt) file.
