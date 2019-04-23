
import requests
import json
import os
import threatgrid
from datetime import datetime
import sys
import configparser
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

with open ('sha.txt', 'r') as fp:
    shalist = json.loads(fp.read())
configFile = 'api.cfg'

# Read the config file to get settings
config = configparser.ConfigParser()
config.read(configFile)
api_key = config.get('ThreatGrid', 'apiKey')
api_key = str.rstrip(api_key)

# intialize  threatgrid objects
here = os.path.abspath(os.path.dirname(__file__))
threatgrid_api = threatgrid.tg_account(api_key)

# step one query threatgrid for the sha_256 and extract relevant information
# important info is sample id
# import info is threat_score
def findDomains(sha_256_1):
    print("Picking up the next sha from the list: {0} ".format(sha_256_1))
    if sha_256_1 == "b75fd580c29736abd11327eef949e449f6d466a05fb6fd343d3957684c8036e5":
        return
    elif sha_256_1 == "078a122a9401dd47a61369ac769d9e707d9e86bdf7ad91708510b9a4584e8d49":
        return
    elif sha_256_1 == "7e54dceecd3d3a23a896e971ae4bb9e71a64a5c1c3b77ac1c64241c55c1b95bb":
        return
    elif sha_256_1 == "8db0d7f3a27291f197173a1e3a3a7242fc49deb2d06f90598475c919417a1c7a" :
        return
    elif sha_256_1 == "f52bfac9637aea189ec918d05113c36f5bcf580f3c0de8a934fe3438107d3f0c" :
        return
    elif sha_256_1 == "fa1789236d05d88dd10365660defd6ddc8a09fcddb3691812379438874390ddc" :
        return
    elif sha_256_1 == "1eb15091d4605809a0a78e9c150e764c9253f9249a7babe4484c27d822d59900" :
        return
    samples = threatgrid_api.get("/search/submissions?q={}".format(sha_256_1))
    print (samples)
    if (samples == "Response [408]"):
        return
    sample_ids = {}
    behaviors = []
    for sample in samples['data']['items']:
        sample_ids[sample["item"]["sample"]] = sample["item"]["analysis"]["threat_score"]
        for behavior in sample["item"]["analysis"]["behaviors"]:
            behaviors.append(behavior["title"])
# Prepare TG report to screen with average score after number of runs and behavior
    behaviors = set(behaviors)
    num_of_runs = len(sample_ids)
    total = 0
    sample_string = ""
    for sample, score in sample_ids.items():
        total = total + score
        sample_string = "{}{},".format(sample_string,sample)
        #average = total/num_of_runs
    #print ("Sample was run {} times and results in an average score of {}".format (num_of_runs, average))
    print ("Behavior of sample:")
    for value in behaviors:
        print (value)
        sample_string = sample_string[:-1]
    #print (sample_string)
    domains = threatgrid_api.get("/samples/feeds/domains?sample={}&after=2017-2-2".format(sample_string))
    domain_list = []
    ip_list = []
    if (domains == "Response [408]"):
        return
    for domain in domains["data"]["items"]:
        if domain["relation"] == "dns-lookup":
            for item in domain["data"]["answers"]:
                domain_list.append(domain["domain"])
                ip_list.append(item)
    print ("\nAssociated domains:\n")
    print ("\n".join(domain_list))
    print ("\n samples made outbound connections on following IPs:\n")
    print ("\n".join(ip_list))
    print ("Finished Building list for Next Mission with Umbrella Investigate ...")
    with open(os.path.join(here, "domainsipaddr.txt"), "a") as file:
        for listitem in domain_list:
           file.write('%s\n' % listitem)
        for listit in ip_list:
           file.write('%s\n' % listit)
        #file.write(json.dumps(domain_list))
        #file.write(json.dumps(ip_list))
        file.close()
for items in shalist:
    findDomains(items)
