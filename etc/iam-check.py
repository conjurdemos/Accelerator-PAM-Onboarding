# iam-checky.py    -*-Python-*-

# Updated: <2023-10-02 16:43:08 david.hisel>

# PRE-REQUIREMENTS
#   Python3
#   pip3 install botocore
#   pip3 install schema

#   *** FILL IN THE USER VARIABLE SECTION

import requests
import json
from schema import Schema, And
from urllib.parse import quote

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import get_credentials
from botocore.session import Session
from botocore.session import get_session

###
### USER VARIABLE SECTION - User Fills these in
### 
CONJUR_API_URL = "https://example-demo-toolshed.secretsmgr.cyberark.cloud/api"
CONJUR_IDENTITY = "host/data/toolshed/111111111111/toolshed"
CONJUR_AWS_ROLE_ARN = "arn:aws:iam::111111111111:role/toolshed"
CONJUR_AUTHENTICATOR = "authn-iam/toolshed"
CONJUR_ACCOUNT = "conjur"
###
###


########################################
########################################

REGION = "us-east-1"
SERVICE = "sts"
HOST = "{service}.amazonaws.com".format(service=SERVICE)
URL = "https://{host}/?Action=GetCallerIdentity&Version=2011-06-15".format(host=HOST)
METHOD = "GET"
AWS_HEADERS_SCHEMA = Schema({
    "Host": And(str, len),
    "X-Amz-Date": And(str, len),
    "X-Amz-Security-Token": And(str, len),
    "Authorization": And(str, len)
})
AUTHENTICATE_URL = "{url}/{authenticator}/{account}/{identity}/authenticate"

def fetch_aws_headers():
    s = get_session()
    stsclient = s.create_client('sts', region_name='us-east-1')
    credentials = stsclient.assume_role(
        RoleArn=CONJUR_AWS_ROLE_ARN,
        RoleSessionName="iam-check")
    sess = Session()

    creds = sess.get_credentials()
    creds.access_key = credentials['Credentials']['AccessKeyId']
    creds.secret_key = credentials['Credentials']['SecretAccessKey']
    creds.token = credentials['Credentials']['SessionToken']
    sigv4 = SigV4Auth(creds, SERVICE, REGION)
    req = AWSRequest(method=METHOD, url=URL, headers={"Host": HOST})
    sigv4.add_auth(req)
    req = req.prepare()
    aws_headers = dict(req.headers)
    AWS_HEADERS_SCHEMA.validate(aws_headers)
    return aws_headers

 
def authenticate_conjur_with_iam(headers:dict):

    url = CONJUR_API_URL
    identity = CONJUR_IDENTITY
    
    encoded_identity = quote(identity, safe="")
    authn_url = AUTHENTICATE_URL.format(url=url, authenticator=CONJUR_AUTHENTICATOR, account=CONJUR_ACCOUNT,
                                        identity=encoded_identity)
    print("######################################")
    print("### For troubleshooting purposes only.")
    print("###")
    print("### NOTE: These curl statements are printed only,")
    print("###       they can be copy pasted into your terminal for troubleshooting.")
    print("")
    print("###")
    print("### Here is the computed authentication url.")
    print("URL: " + authn_url)
    print("")
    print("###")
    print("### Here are the headers that were generated using the AWS SigV4Auth method.")
    print("HEADERS: " + json.dumps(headers))
    print("")


    hs = ""
    for h in headers:
        hs = "-H '{}: {}' {}".format(h, headers[h], hs)

    print("###")
    print("### Here is a curl call that will POST to AWS STS to help troublehsoot configuration of the role.")
    print("AWS CURL:\ncurl -D - {} '{}'".format(hs, URL))
    print("")

    print("###")
    print("### Here is a curl call that will POST to Conjur to help troublehsoot configuration of Conjur.")
    print("CONJUR CURL:\ncurl -D - -H 'Accept-Encoding: base64' '{}' -d'{}'".format(authn_url, json.dumps(headers)))
    print("")
    

    response = requests.post(authn_url, headers={ 'Accept-Encoding': 'base64'}, data=json.dumps(headers), verify=True)
    token = response.content.decode("utf-8").strip()
    return dict(token=token)
 
headers = fetch_aws_headers()
token = authenticate_conjur_with_iam(headers)

print("###")
print("### Here is the sessino token returned from Conjur.")
print("### If you see a token, and not an error message, then the Conjur AWS Authenticator is ready.")
print("TOKEN: "+ token["token"])
