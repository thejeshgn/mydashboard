
import uuid
import json

from oauthlib import oauth2
from oauthlib.oauth2 import WebApplicationClient
from oauthlib.common import generate_token, urldecode
from oauthlib.common import to_unicode, PY3, add_params_to_uri

try:
    from urlparse import urljoin
    import urllib2 as http
except ImportError:
    from urllib import request as http
    from urllib.parse import urljoin


OAUTH1 = 'oauth1'
OAUTH2 = 'oauth2'
DEFAULT_OAUTH = OAUTH2


#We can load this from a properties file
PROVIDERS = {
  'googleplus': {"type":"oauth2",
                 "auth_url":"https://accounts.google.com/o/oauth2/auth", 
                 "token_url":"https://accounts.google.com/o/oauth2/token",
                 "token_url_method":"POST",
                 "profile_email_url":"https://www.googleapis.com/oauth2/v3/userinfo?alt=json",
                 "profile_email_key":"email",
                 "profile_account_key":"sub",
                 "client_id":"",
                 "client_secret":"",
                 "scope":['https://www.googleapis.com/auth/userinfo.email','https://www.googleapis.com/auth/userinfo.profile'],
                 "optional_params":{"access_type":"offline", "approval_prompt":"force"} # {'<parameter_name>': '<value>'} that needs to be sent
                 },
  'our': {"type":"oauth2",
                 "auth_url":"http://localhost:8000/o/authorize", 
                 "token_url":"http://localhost:8000/o/token/",
                 "token_url_method":"POST",
                 "profile_email_url":"http://localhost:8000/api/user",
                 "profile_email_key":"email",
                 "profile_account_key":"id",
                 "client_id":"vx8S4bijGuMciQZpqkxmJskCxqIfWZXe78OulMzq",
                 "client_secret":"ITkgjOBAtvtdyqPlg47lkexmc1kF3I9wGNOHcqZkigqNtzFKcANwV2zpvhb101KiwTTJ2zMMuHqRwFGcsFo86YN96IrzJ08k5N1MtyaLUvIfGHipyd3g6rgybqKLYww2",
                 "scope":[],
                 "optional_params":{"access_type":"offline", "approval_prompt":"force"} # {'<parameter_name>': '<value>'} that needs to be sent
                 }                 
}

#================FOR TESTING =========================
provider = "our"
redirect_url = "http://localhost:8080/hello"
import os 
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
#======================================================

def make_request(url, headers, body, method="POST"):
  req = None
  if method == "GET":
     uri = add_params_to_uri(url, body)
     req = http.Request(uri, headers=headers)
  else:
    method = "POST"
    uri = url
    req = http.Request(uri, headers=headers, data=body)
  req.get_method = lambda: method.upper()
  try:
      resp = http.urlopen(req)
      content = resp.read()
      resp.close()
      return resp, content
  except http.HTTPError as resp:
      content = resp.read()
      resp.close()
      return resp, content


def init(provider,redirect_url):
  scope = PROVIDERS[provider]['scope']
  client_id = PROVIDERS[provider]['client_id']
  auth_url = PROVIDERS[provider]['auth_url']
  
  #design a better way to create state, 
  state = str(uuid.uuid4())
  #may as below
  #from webapp2_extras import security
  #state = security.generate_random_string(30, pool=security.ASCII_PRINTABLE)

  client = WebApplicationClient(client_id=client_id,state=state)

  optional_params = {}
  if (PROVIDERS[provider]).has_key("optional_params"):
    optional_params = PROVIDERS[provider]["optional_params"]
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
  authorization_url = client.prepare_request_uri(auth_url, redirect_uri=redirect_url,state=state, scope=scope,**optional_params)
  return client, str(authorization_url), state




def process_callback(callback_url, state, provider, redirect_url):
  client_secret = PROVIDERS[provider]['client_secret']
  
  client_id = PROVIDERS[provider]['client_id']
  scope = PROVIDERS[provider]['scope']
  client = WebApplicationClient(client_id=client_id,state=state)

  response = client.parse_request_uri_response(callback_url, state=state) 
  print str(response)


  token_request_body = client.prepare_request_body(client_id=client_id, code=response['code'], body='',redirect_uri=redirect_url, client_secret=client_secret)
  token_url = PROVIDERS[provider]['token_url']
  token_url_method = PROVIDERS[provider]['token_url_method']
  resp, token_content = make_request(url=token_url,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                body=token_request_body,
                method = token_url_method
            )
  print str(token_content)
  token_content_json = json.loads(token_content)
  return token_content_json

def get_user(token_content,provider, header=False):
  client_id = PROVIDERS[provider]['client_id']
  client_secret = PROVIDERS[provider]['client_secret']
  
  client = WebApplicationClient(client_id=client_id,token=token_content["access_token"])
  profile_email_url = PROVIDERS[provider]['profile_email_url']
  email_request_body = {"access_token":token_content["access_token"]}
  resp, profile_content = make_request(url=profile_email_url,
                headers={"Authorization":"Bearer "+token_content["access_token"]},
                body=email_request_body,
                method="GET"
            )
  profile_email_key = PROVIDERS[provider]["profile_email_key"]
  profile_account_key = PROVIDERS[provider]["profile_account_key"]

  print str(profile_content)
  print str(resp)
  profile_content_json = json.loads(profile_content)
  return profile_content_json[profile_email_key], profile_content_json[profile_account_key]
