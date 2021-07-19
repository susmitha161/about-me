import os
import logging
import json
import requests

VAULT_URL = "https://apistaging.vault.secrets.prd.data.sfdc.net:443/v1"
VAULT_LOGIN = "/auth/cert/login"
VAULT_DEFAULT_MOUNT_POINT = "kv"
#VAULT_KV = "/kv/data/sravurutest1/"

logging.basicConfig(level=logging.NOTSET)

class Vault:
	"""
	The Vault object that is used to access Vault
	"""
	def __init__(self, vault_role, vckey, path, vccert, mount_point=VAULT_DEFAULT_MOUNT_POINT, addr=VAULT_URL):
		self.mount_point = mount_point
		self.vault_role = vault_role
		self.path = path
		self.login(vccert, vckey)

	def login(self, vccert, vckey):
		"""
		Authenticate to the Vault
		"""
		try:
			uri = VAULT_URL + VAULT_LOGIN
			logging.info("Login to vault {} ".format(uri))
			body = json.dumps({'name': self.mount_point + '_' + self.vault_role})
			logging.debug("calling API: {}".format(uri))
			r = requests.post(uri, cert=(vccert, vckey)
						, data=body
                        , headers={"Content-Type": "application/json"})
			r.raise_for_status()
			response = r.json()
			logging.info("Logged into vault successfully")
		except requests.exceptions.HTTPError as e:
			self.do_request(e)
			self.token = None
		self.token = response["auth"]["client_token"]

	def do_request(self, e):
		logging.error(' status_code  : ' + str(e.response.status_code))
		logging.error(' url          : ' + e.response.url)
		logging.error(' response body : ' + e.response.text)


	def read(self, name, vault_url=VAULT_URL):
		"""
		Retrieve Secret from Vault
    	"""
		token = self.token
		logging.info("Reading secret")
		try:
			uri = vault_url + self.path + name
			r = requests.get(uri, headers={"Content-Type": "application/json","X-Vault-Token": token})
			secret = r.json()
			print(secret['data']['data'])
			return secret
		except requests.exceptions.HTTPError as e:
			self.do_request(e)
			return None
		except KeyError as k:
			logging.error("Secret Not Found!!!" + str(k))
			return None
		logging.info('Secret successfully retrieved')

	def write(self, name, value, vault_url=VAULT_URL):
		"""
		Update secret to Vault
		"""
		token = self.token
		try:
			uri = vault_url + self.path + name
			body = json.dumps({"data": {"secret": value}})
			requests.post(uri, data=body, headers={"Content-Type": "application/json", "X-Vault-Token": token})
		except requests.exceptions.HTTPError as e:
			self.do_request(e)
			return None
		logging.info("Secret successfully updated")


rpath = input("Enter Vault Path:")
# a = input("Enter access attributes(r/rw/none):")
vrole = rpath + "-rw"
vpath = "/kv/data/" + rpath + "/"

cert_path = input("Enter Cert Path:")
# vault_ca_cert = os.path.join(os.environ.get('HOME'), 'dktool_repo','ca','cacerts.pem')
def_ca_bundle = os.path.join(cert_path, 'ca','cacerts.pem')
def_certs_path = os.path.join(cert_path, 'user', 'client')
vault_client_cert = os.path.join(def_certs_path, 'certificates', 'client.pem')
vault_client_key = os.path.join(def_certs_path, 'keys', 'client-key.pem')

os.environ['REQUESTS_CA_BUNDLE']=def_ca_bundle

c=Vault(vault_role = vrole, path = vpath, vccert=vault_client_cert, vckey=vault_client_key)
# c=Vault("sravurutest1-rw")
# c.read('testsecret')
# c.write('testsecret6', 'sacr3p')
c.read('testsecret6')