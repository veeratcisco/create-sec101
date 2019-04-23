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
investigate_url = "https://investigate.api.umbrella.com/domains/categorization/"

# create header for authentication and set limit of sample return to 1
headers = {
    'Authorization': 'Bearer ' + investigate_api_key,
    'limit': '1'
}

print(url_post)


def get_domain_disposition(get_url, domain):
    print(get_url)
    req = requests.get(get_url, headers=headers)
    if req.status_code == 200:
        output = req.json()
        domainOutput = output[domain]
        domainStatus = domainOutput["status"]
        if (domainStatus == -1):
            print("SUCCESS: The domain %(domain)s is found MALICIOUS at %(time)s" %
                  {'domain': domain, 'time': time})
            return "bad"
        elif (domainStatus == 1):
            print("SUCCESS: The domain %(domain)s is found CLEAN at %(time)s" %
                  {'domain': domain, 'time': time})
            return "clean"
        elif (domainStatus == 0):
            print("SUCCESS: The domain %(domain)s is found UNDEFINED / RISKY at %(time)s" %
                  {'domain': domain, 'time': time})
            return "risky"
    else:
        print(
            "An error has ocurred with the following code %(error)s, please consult the following link: https://docs.umbrella.com/investigate-api/" %
            {'error': req.status_code})
        return "error"


def handle_domain_status():
    domain_list = []
    with open('domainsipaddr.txt') as inputfile:
        for line in inputfile:
            if line[0] == "#" or line.strip() == "Site":
                pass
            else:
                domain_list.append(line.strip())
    time = datetime.now().isoformat()
    domain_list_r = []
    domin_filter_ip = []
    domain_final = []
    for i in domain_list:
        if i not in domain_list_r:
            domain_list_r.append(i)
    domain_filter_ip = domain_list_r
    print(domain_filter_ip)
    for whatip in domain_filter_ip:
        if is_valid_ipv4_address(whatip) == False:
            domain_final.append(whatip)
            domain_list = domain_final
            print(domain_list)
            # loop through all domains
    print("We found dulicates and pruned the list :\n")
    for domain in domain_list:
        print(domain)
        get_url = investigate_url + domain + "?showLabels"
        status = get_domain_disposition(get_url, domain)
        if status != "error":
            if (status == "bad") or (status == "risky"):
                post_enforcement(domain)
            else:
                print(f"Found clean domain, ignoring enforcement on {domain}")
        else:
            print("got error from Umbrella investigate")


def post_enforcement(domain):
    # check if there is a threat grid sample with a score higher than or equal to 90, if so upload to custom block list
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
    # POST REQUEST: post request
    request_post = requests.post(url_post, data=json.dumps(data), headers={
        'Content-type': 'application/json', 'Accept': 'application/json'})
    if (request_post.status_code == 202):
        print("\n")
        print(
            "SUCCESS: The domain %(domain)s has an associated sample with Hash: %(hash)s and Threat Score: %(score)i at %(time)s" % {
                'domain': domain, 'hash': hash_sample, 'score': score_sample, 'time': time})
        print("\n")
    # error handling
    else:
        print(
            "An error has ocurred with the following code %(error)s, please consult the following link: https://docs.umbrella.com/investigate-api/" %
            {'error': request_post.status_code})


if __name__ == "__main__":
    handle_domain_status()
