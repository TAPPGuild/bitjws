# Install requirements: pip install requests
import requests
import bitjws

# Load existing private key. In this example the server always
# create a new private key while the client loads an existing one.
wif = "KxZUqanyzZEGptbauar66cQo8bfGHwDauHogkxCaqTeMGY1stH6E"
priv = bitjws.wif_to_privkey(wif)
privkey = bitjws.PrivateKey(priv)
assert wif == bitjws.privkey_to_wif(privkey.private_key)
# The resulting bitcoin address can be derived for debugging
# purposes.
my_pubkey = privkey.pubkey.serialize()
my_address = bitjws.pubkey_to_addr(my_pubkey)
assert my_address == "1G9sChbyDSmuAXNVpjuRwakTmcHdxKGqpp"
print("My WIF key: {}".format(wif))
print("My key address: {}".format(my_address))

# Prepare a request to be sent. This one uses a single custom
# parameter named 'echo'.
echo_msg = 'hello'
data = bitjws.sign_serialize(privkey, echo=echo_msg)
# Send and receive signed requests.
resp = requests.post('http://localhost:8001/', data=data)
headers, payload = bitjws.validate_deserialize(resp.content.decode('utf8'))
print(headers)  # headers['kid'] contains the key used by the server.
print(payload)

# In this example the server returns a response containing the
# echo parameter specified earlier and also a param named 'address'.
assert payload['echo'] == echo_msg
assert payload['address'] == my_address
