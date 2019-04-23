#!/usr/bin/env python

import requests
import json
import pickle
import configparser
from datetime import datetime
import sys
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass
# Specify the config file to read from
configFile = 'api.cfg'

# Read the config file to get settings
config = configparser.ConfigParser()
config.read(configFile)
ISE_ERSUSER = config.get('ISE', 'userName')
ISE_ERSUSER = str.rstrip(ISE_ERSUSER)

ISE_ERSPASSWORD=config.get('ISE', 'passWord')
ISE_ERSPASSWORD=str.rstrip(ISE_ERSPASSWORD)


ISE_HOSTNAME=config.get('ISE', 'hostName')
ISE_HOSTNAME=str.rstrip(ISE_HOSTNAME)

ISE_ENDPOINT="12:22:33:44:55:66"
def createPayload(maclist, policy):
    data_to_send = {
        'OperationAdditionalData': {
            'additionalData' : [{ 
                'name': 'macAddress',
                f'value': maclist 
                }, 
                {
                    'name': 'policyName',
                    f'value': policy 
                    }]
        }
    }
    return data_to_send

url = "https://" + ISE_ERSUSER + ":" + ISE_ERSPASSWORD + "@" + ISE_HOSTNAME + "/ers/config/ancpolicy"

with open ('macaddr.txt', 'r') as fp:
    maclist = json.loads(fp.read())

headers = {
    'content-type': "application/json",
    'accept': "application/json"
    }

response = requests.request("GET", url, verify=False, headers=headers)

namelist=" "
if(response.status_code == 200):
    resp_json = response.json()
    policies = resp_json["SearchResult"]["resources"]
    for policy in policies:
        namelist = policy["name"]
    print("\nI've Found the Quarantine Policy {0} to Nuke the Rogue computers from the corp network... \n".format(namelist) )

else:
        print("An error has ocurred with the following code %(error)s" % {'error': response.status_code})


url = url = "https://" + ISE_ERSUSER + ":" + ISE_ERSPASSWORD + "@" + ISE_HOSTNAME + "/ers/config/ancendpoint/apply"
print(url)
for items in maclist:
    payload = "{\r\n    \"OperationAdditionalData\": {\r\n    \"additionalData\": [{\r\n    \"name\": \"macAddress\",\r\n    \"value\": \""+ items + "\"\r\n    },\r\n    {\r\n    \"name\": \"policyName\",\r\n    \"value\": \"" + namelist + '"' + "\r\n    }]\r\n  }\r\n}"
    #payload = createPayload(items,namelist)
    print(json.dumps(payload,sort_keys=True,indent=3))
    response = requests.request("PUT", url, data=payload, verify=False, headers=headers)
    if(response.status_code == 204):
        print("Done!..Applied Quarantine policy to the rouge endpoint...MAC: {0} Threat is now contained....".format(items))
    else:
        print("An error has ocurred with the following code %(error)s" % {'error': response.status_code})
