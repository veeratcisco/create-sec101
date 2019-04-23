#!/usr/bin/env python

import json
import os
import sys
import requests
import configparser
from pprint import pprint
# Disable Certificate warning
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Specify the config file to read from
configFile = 'api.cfg'

# Read the config file to get settings
config = configparser.ConfigParser()
config.read(configFile)
client_id = config.get('AMP', 'clientId')
client_id = str.rstrip(client_id)

api_key = config.get('AMP', 'apiKey')
api_key = str.rstrip(api_key)
def getAMP(url):
	try:
	    response = requests.get(url, verify=False)
	    # Consider any status other than 2xx an error
	    if not response.status_code // 100 == 2:
	        return "Error: Unexpected response {}".format(response)
	    try:
	        return response.json()
	    except:
	        return "Error: Non JSON response {}".format(response.text)
	except requests.exceptions.RequestException as e:
	    # A serious problem happened, like an SSLError or InvalidURL
	    return "Error: {}".format(e)


#Enter the standard AMP event id for type of event for Malware... it is 1107296272
event_id = "1107296272"

events_url = "https://{}:{}@api.amp.cisco.com/v1/events".format(client_id,api_key)
print (events_url)
events1 = getAMP(events_url)
sha_list= {}
iplist=[]
maclist=[]
print (json.dumps(events1, indent=4, sort_keys=True))
for events1 in events1["data"]:
	if events1["event_type_id"] == 1107296272:
		sha_list[events1["computer"]["hostname"]] = json.dumps(events1["file"]["identity"]) + "\n IP: " + events1["computer"]["network_addresses"][0]["ip"] + "\n Mac: " + events1["computer"]["network_addresses"][0]["mac"]
		iplist.append(events1["file"]["identity"]["sha256"])
		maclist.append(events1["computer"]["network_addresses"][0]["mac"])
	else:
		continue
here = os.path.abspath(os.path.dirname(__file__))


with open(os.path.join(here, "macaddr.txt"), "w") as file:
	file.write(json.dumps(maclist))
file.close()
with open(os.path.join(here, "sha.txt"), "w") as file:
	file.write(json.dumps(iplist))
file.close()
pprint("Hosts, their IPs and Mac address where malaware was executed:" )
print(" ")
pprint(sha_list)
pprint(maclist)
	