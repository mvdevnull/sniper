#!/usr/bin/env python3

import sys
import os
import io
import argparse
import getpass
import json

sys.path.append('../')
from nessrest import ness6rest
  
# Print error function
def print_err(str_error, fatal=False):
  sys.stderr.write('ERROR: ' + str_error + '\n')
  if fatal:
    exit('Exiting due to fatal error.')

# Parse command line options
parser = argparse.ArgumentParser(description='Download completed nessus scans.')
parser.add_argument('-s', '--server', help='IP address of Nessus API endpoint', default='127.0.0.1')
parser.add_argument('-p', '--port', help='port number of Nessus API endpoint', type=int, default=8834)
parser.add_argument('-f', '--format', help='report format', choices=['nessus', 'html', 'csv', 'db'], default='nessus')
parser.add_argument('--dbpasswd', help='scan db format password', default=None)
parser.add_argument('-c', '--capath', help='certificate authority path', default=None)
parser.add_argument('-t', '--trash', help='include trash folder', action='store_true', default=False)
parser.add_argument('--insecure', help='boldly go forth and ignore cert errors', action='store_true', default=False)
group = parser.add_mutually_exclusive_group()
group.add_argument('-k', '--keyfile', help='API key file in json format')
group.add_argument('-u', '--user', help='Nessus user instead of API key (password prompt will occur)')
args = parser.parse_args()

# Get keys
keys = None
password = None
if args.keyfile:
  if os.path.isfile(args.keyfile):
    try:
      f_key = open(args.keyfile, 'r')
      try:
        keys = json.loads(f_key.read())
      except ValueError as err:
        print_err(str(err))
        print_err('could parse read key file "' + args.keyfile + '".', True)
      f_key.close()
    except IOError:
      print_err('could not read key file "' + args.keyfile + '".', True)
  else:
    print_err('"' + args.keyfile + '" is not a valid file.', True)
elif args.user:
  password = getpass.getpass()
else:
  parser.error('No action taken, either a key file or user must be provided')

if args.capath and not os.path.isdir(args.capath):
  print_err('CA path "' + args.capath + '" not found.', True)

if args.format == "db" and args.dbpasswd is None:
  print_err('Format is db but no exported db password was specified, use --dbpasswd to specify', True)

nessus_url = "https://" + args.server + ":" + str(args.port)
insecure = args.insecure
localhost = args.server == 'localhost' or args.server[:4] == '127.' or args.server == '::1'

# allow localhost connections to proceed without warning, but warn otherwise if CA not set
if not args.capath:
  if localhost:
    insecure = True
  elif not insecure:
    # warn if user hasn't supplied a CA Path, but might expect security or bump into TLS errors later
    print('WARNING:  No CA path explicitly set. Connection to ' + nessus_url + ' could fail due to TLS/SSL server authentication')

scanner = None
if keys:
  scanner = ness6rest.Scanner(url=nessus_url, api_akey=keys['accessKey'], api_skey=keys['secretKey'], insecure=insecure, ca_bundle=args.capath)
elif password:
  scanner = ness6rest.Scanner(url=nessus_url, login=args.user, password=password, insecure=insecure, ca_bundle=args.capath)
else:
  print_err('Failed to understand API key or password (this is probably a script BUG)', True)

# Get all reports
if scanner:
  scanner.action(action='scans', method='get')
  folders = scanner.res['folders']
  scans = scanner.res['scans']
  # create scan subfolders
  for f in folders:
    if not os.path.exists(f['name']):
      if f['type'] == 'trash':
        if args.trash:
          os.mkdir(f['name'])
      else:
        os.mkdir(f['name'])
  # try download and save scans into each folder the belong to
  for s in scans:
    scanner.scan_name = s['name']
    scanner.scan_id = s['id']
    folder_name = next(f['name'] for f in folders if f['id'] == s['folder_id'])
    folder_type = next(f['type'] for f in folders if f['id'] == s['folder_id'])
    # skip trash items?
    if folder_type == 'trash' and not args.trash:
      continue
    if s['status'] == 'completed':
      file_name = '%s_%s.%s' % (scanner.scan_name, scanner.scan_id, args.format)
      file_name = file_name.replace('\\','_')
      file_name = file_name.replace('/','_')
      file_name = file_name.strip()
      relative_path_name = folder_name + '/' + file_name
      # PDF not yet supported
      # python API wrapper nessrest returns the PDF as a string object instead of a byte object, making writing and correctly encoding the file a chore...
      # other formats can be written out in text mode
      file_modes = 'wb'
      # DB is binary mode
      #if args.format == "db":
      #  file_modes = 'wb'
      with io.open(relative_path_name, file_modes) as fp:
        if args.format != "db":
          fp.write(scanner.download_scan(export_format=args.format))
        else:
          fp.write(scanner.download_scan(export_format=args.format, dbpasswd=args.dbpasswd))

else:
  print_err('Failed to use scanner at ' + nessus_url + '.', True)

