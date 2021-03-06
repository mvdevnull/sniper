# sniper

## About
sniper is a command line host discovery tool used to scan large networks

### Core Features
###### Scanning
* db_nmap (all nmap results centralized in Metasploit database)
* metasploit discovery (auxiliary results centralized in Metasploit database)
* eyewitness web thumbnails (centralized in /var/www/html/sniper)
###### Data Updates
* OS name/flavor/SP confirmation 
###### Reporting
* Insecure protocols
* Gaping holes

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
* Other potential features are noted in the [/docs/todo.txt](https://github.com/mvdevnull/sniper/blob/master/docs/todo.txt) file.
