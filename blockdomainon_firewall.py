
import requests
from bravado.client import SwaggerClient
from bravado.requests_client import RequestsClient

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": "Bearer "
}

auth_payload = '''
{
  "grant_type": "password",
  "username": "admin",
  "password": "C1sco12345"
}
'''



hostname = "https://198.18.133.8"

def login():
    r = requests.post(hostname + "/api/fdm/v1/fdm/token", data=auth_payload, verify=False, headers=headers)
    access_token = "Bearer %s" % r.json()['access_token']
    headers['Authorization'] = access_token

def get_spec_json():
    http_client = RequestsClient()
    http_client.session.verify = False
    http_client.session.headers = headers

    client = SwaggerClient.from_url(hostname + '/apispec/ngfw.json', http_client=http_client, config={'validate_responses':False})
    return client

# ----------------
def create_url_object(client):
    url_object = client.get_model("URLObject")(type="urlobject")
    url_object.name = "Blockbadguys"
    #Mission TODO: Enter the domain you found malicious or questionable in Umbrella Investigate to block on FTD
    url_object.url = "7tno4hib47vlep5o.tor2web.com"
    client.URLObject.addURLObject(body=url_object).result()


def create_access_rule(client):
    # get access policy first
    access_policy = client.AccessPolicy.getAccessPolicyList().result()['items'][0]
    # fetch the url object we created
    url_object = client.URLObject.getURLObjectList(filter="name:Blockbadguys").result()['items'][0]
    # reference model (name, id, type)
    ReferenceModel = client.get_model("ReferenceModel")

    # create embedded app filter
    embedded_url_filter = client.get_model("EmbeddedURLFilter")(type="embeddedurlfilter")
    embedded_url_filter.urlObjects = [ReferenceModel(id=url_object.id, type=url_object.type)]
    
    # Access Rule model
    access_rule = client.get_model("AccessRule")(type="accessrule")
    access_rule.name = "block_thebadguys"
    access_rule.urlFilter = embedded_url_filter
    client.AccessPolicy.addAccessRule(body=access_rule, parentId=access_policy.id).result()
    print("\nDone! Blocked the Custom URL on the NGFW....Using FDM REST API....\n By the way you can block domains/URLS/IPs using FMC REST API as well ....\n")

if __name__ == '__main__':
    login()
    client = get_spec_json()
    create_url_object(client)
    create_access_rule(client)