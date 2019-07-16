import sys
sys.path.insert(0, '/usr/local/src/misc/sniper.2019/tools/dev-testing/nessrest/nessrest-0.40/nessrest')
import ness6rest
import argparse
from pprint import pprint

nessus_url = "https://10.67.133.25:8834"
nessus_login = "root"
nessus_password = "Password1!"
nessus_policyname = "Identify-OS_updated_by_sniper"

parser = argparse.ArgumentParser()
parser.add_argument('--target', required=True)
args = parser.parse_args()



scan = ness6rest.Scanner(url=nessus_url, login=nessus_login, password=nessus_password, insecure=True)


if  scan.policy_exists(name=nessus_policyname):
	scan.policy_delete(name=nessus_policyname)
scan.policy_add(name=nessus_policyname, plugins="11936")

#TODO - can't figure out format for adding creds
#scan.policy_add_creds(credentials.WindowsPassword=[(username="administrator", password="foobar")])
#scan.policy_add_creds(credentials=[SshPassword(username="admin", password="pass")])

print (scan.policy_id)
pprint (vars(scan))

#print str(scan._scan_template_uuid[0])
#print (scan.res["policy_id"])
#print (scan.res)





#scan.scan_add(targets=args.target, template="custom", name="", start="")
scan.scan_add(targets=args.target)





#scan.scan_run()
#if  scan.policy_exists(name=nessus_policyname):
#        scan.policy_delete(name=nessus_policyname)





