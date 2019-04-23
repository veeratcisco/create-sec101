from datetime import datetime
import json
import requests
import socket
import configparser
def is_valid_ipv4_address(address):
    try:
        print("Veer")
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            print(address)
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

# Read the config file to get settings
configFile = 'api.cfg'
config = configparser.ConfigParser()
config.read(configFile)
enforcement_api_key = config.get('Enforcement', 'apiKey')
enforcement_api_key = str.rstrip(enforcement_api_key)

investigate_api_key = config.get('Investigate', 'token')
investigate_api_key = str.rstrip(investigate_api_key)


# URL needed to do POST requests
event_url = "https://s-platform.api.opendns.com/1.0/events"

# URL needed for POST request
url_post = event_url + '?customerKey=' + enforcement_api_key

# URL needed for the domain status and category
investigate_url = "https://investigate.api.umbrella.com/samples/"

#create header for authentication and set limit of sample return to 1
headers = {
'Authorization': 'Bearer ' + investigate_api_key,
'limit': '1'
}
print(url_post)
try:
    # loop through .txt file and append every domain to list, skip comments
    domain_list = []
    with open('domainsipaddr.txt') as inputfile:
         for line in inputfile:
            if line[0] == "#" or line.strip() == "Site":
                pass
            else:
                domain_list.append(line.strip())

    # time for AlertTime and EventTime when domains are added to Umbrella
    time = datetime.now().isoformat()
    domain_list_r = []
    domin_filter_ip = []
    domain_final = []
    for i in domain_list:
       if i not in domain_list_r:
          domain_list_r.append(i)
    domain_filter_ip = domain_list_r
    print (domain_filter_ip)

    for whatip in domain_filter_ip:
        if is_valid_ipv4_address(whatip) == False:
            domain_final.append(whatip)
    domain_list=domain_final
    print (domain_list)
    # loop through all domains
    print("We found dulicates and pruned the list :\n")
    for domain in domain_list:
        print(domain)
        # assemble the URI, show labels give readable output
        get_url = investigate_url + domain
        # do GET request for the domain status and category
        request_get = requests.get(get_url, headers=headers)

        if(request_get.status_code == 200):
            # store threat grid json output in variable
            output = request_get.json()
            if output["samples"] == []:
                continue

            sample = output["samples"][0]
            hash_sample = sample["sha256"]
            score_sample = sample["threatScore"]

            # check if there is a threat grid sample with a score higher than or equal to 90, if so upload to custom block list
            if score_sample >= 90:

                data = {
                    "alertTime": time + "Z",
                    "deviceId": "ba6a59f4-e692-4724-ba36-c28132c761de",
                    "deviceVersion": "13.7a",
                    "dstDomain": domain,
                    "dstUrl": "http://" + domain + "/",
                    "eventTime": time + "Z",
                    "protocolVersion": "1.0a",
                    "providerName": "Security Platform"
                }
                # POST REQUEST: post request ensembly
                request_post = requests.post(url_post, data=json.dumps(data), headers={
                                             'Content-type': 'application/json', 'Accept': 'application/json'})
                if(request_post.status_code == 202):
                    print("\n")
                    print("SUCCESS: The domain %(domain)s has an associated sample with Hash: %(hash)s and Threat Score: %(score)i at %(time)s" % {
                          'domain': domain, 'hash': hash_sample, 'score': score_sample, 'time': time})
                    print("\n")
                # error handling
                else:
                    print("An error has ocurred with the following code %(error)s, please consult the following link: https://docs.umbrella.com/investigate-api/" %
                          {'error': request_post.status_code})

        else:
            # error handling
            print("An error has ocurred with the following code %(error)s, please consult the following link: https://docs.umbrella.com/enforcement-api/reference/" %
                {'error': request_get.status_code})

except KeyboardInterrupt:
    print("\nExiting...\n")
