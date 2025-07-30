# sniper

## About
sniper is a command line host discovery tool used to scan large networks.  
sniper saves time by efficiently scanning in a strategic order: 
*1)Discovering only alive hosts in large ranges
*2)TCP ports for only alive hosts
*3)Deep -sV banner scans for tcp ports and will not repeat -sV for queries with no response
*4)runs eyewitness for web frontends 

### Core Features
###### Scanning
* db_nmap (all nmap results centralized in Metasploit database)
* metasploit discovery (auxiliary results centralized in Metasploit database)
* eyewitness web thumbnails (centralized in ./sniper/report.html)
###### Data Updates
* Service banner details
* OS name/flavor/SP confirmation
* Nessus .xml integration
###### Reporting
* Insecure protocols via nmap
* Common findings via Nessus pluginID
* Gaping holes via Nessus pluginID

### Installation
```
git clone https://github.com/mvdevnull/sniper.git
cd sniper
chmod +x ./sniper.sh
msfdb init                                        #Initialize postgres for MSF


```
###### Dependencies
````
apt-get install metasploit-framework              #Install metasploit framework
apt-get install eyewitness                        #Install eyewitness
apt-get install python3-psycopg2                  #Install postgresql python3 library
````
### Usage
```
./sniper.sh                                       #answer questions and wait for scans
msfconsole                                        #run in separate window and wait for new hosts
```

### Future Features (TBD)
* nessus API (standard , gaping holes and compliance)
* Other bugs and potential features are noted in the [/docs/todo.txt](https://github.com/mvdevnull/sniper/blob/master/docs/todo.txt) file.
