# bitjws [![Build Status](https://travis-ci.org/deginner/bitjws.svg?branch=master)](https://travis-ci.org/deginner/bitjws) [![Coverage Status](https://coveralls.io/repos/deginner/bitjws/badge.svg?branch=master&service=github)](https://coveralls.io/github/deginner/bitjws?branch=master) [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/deginner/bitjws?utm_source=share-link&utm_medium=link&utm_campaign=share-link)

JWS ([JSON Web Signature](http://self-issued.info/docs/draft-ietf-jose-json-web-signature.html)) using Bitcoin message signing as the algorithm.


## Install

By default it's expected that [secp256k1](https://github.com/bitcoin/secp256k1) is available, so install it before proceeding; make sure to run `./configure --enable-module-recovery`. If you're using some other library that provides the functionality necessary for this, check the __Using a custom library__ section below.

bitjws can be installed by running `pip install bitjws`.


## Usage

Use this package to produce signed JWS messages using the Bitcoin message signing schema and to validate such messages. The JWS header generated is the following one:

```json
{
  "typ": "JWT",
  "alg": "CUSTOM-BITCOIN-SIGN",
  "kid": <bitcoin_address>
}
```

where "kid" is used to indicate the public part of the key used during signing.


##### Sign a message

```python
import bitjws

mykey = bitjws.PrivateKey()
data = bitjws.sign_serialize(mykey)
```

`sign_serialize` function definition:

```python
def sign_serialize(privkey, expire_after=3600, requrl=None, **kwargs):
    """
    Produce a JWT compact serialization by generating a header, payload, and
    signature using the privkey specified.

    The parameter expire_after is used by the server to reject the payload
    if received after current_time + expire_after. Set it to None to
    disable its use.

    The parameter requrl is optionally used by the server to reject the
    payload if it is not delivered to the proper place, e.g. if requrl is
    set to https://example.com/api/login but sent to a different server or
    path then the receiving server should reject it.

    Any other parameters are passed as is to the payload.
    """
```


##### Validate a message

```python
import bitjws

header, payload = bitjws.validate_deserialize(data)
```

`validate_deserialize` may raise `bitjws.InvalidMessage` or `bitwjs.InvalidPayload`. Function definition:

```python
def validate_deserialize(rawmsg, requrl=None, check_expiration=True):
    """
    Validate a JWT compact serialization and return the header and
    payload if the signature is good.

    If check_expiration is False, the payload will be accepted even if
    expired.
    """
```

##### Multiple signatures

```python
import bitjws

key1 = bitjws.PrivateKey()
key2 = bitjws.PrivateKey()

data = bitjws.multisig_sign_serialize([key1, key2])
headers, payload = bitjws.multisig_validate_deserialize(data)
```

The other parameters accepted by `multisig_sign_serialize` and `multisig_validate_deserialize` are the same as described for `sign_serialize` and `validate_deserialize`. The data returned and passed to the validate function are different, as the multisig functions use the format described as general JSON serialization in the JWS spec.


##### Utilities and other functionality

Check `tests/` and `example/` for other functions available but not documented above.


## Using a custom library

It's possible to use `bitjws` without the `secp256k1` library, as well with other signing algorithms.

To install `bitjws` without `secp256k1`, use:

```
pip install bitjws --no-deps
pip install base58
```

##### Custom signing/validation

`bitjws` allows custom algorithms to be registered. They are used during signing/validation and are assumed to be an instance of `bitjws.Algorithm`.

First define a new implementation:

```python
algorithm = bitjws.Algorithm(name,
    sign=sign_function,
    verify=verify_function,
    pubkey_serialize=pubkey_serialize_function)
```

And then register it:

```python
bitjws.ALGORITHM_AVAILABLE[algorithm.name] = algorithm
```

To successfully use this algorithm, the following expectations must be met:

 * `sign_function` takes a private key and data to be signed and returns bytes.
 * `verify_function` takes a signature, the original data, and an address (the Bitcoin address or something equivalent for another implementation, like a public key) and returns a boolean (True if verification is successfull, False otherwise).
 * The `pubkey_serialize_function` function takes a single parameter (e.g. a public key) and returns text (e.g. a bitcoin address).
 * The private key has a member named `pubkey`.

Now it's possible to call the sign/validate functions with the parameter `algorithm_name=algorithm.name`.


##### Example of custom implementation using python-bitcoinlib

Run `pip install python-bitcoinlib` if you don't have this custom dependency installed. The following snippet registers a new algorithm as mentioned above and uses a sample key for a complete example.

```python
import bitjws
from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from bitcoin.signmessage import BitcoinMessage, VerifyMessage, SignMessage

# Compatibility functions.

def sign(privkey, data):
    return SignMessage(privkey, BitcoinMessage(data))

def verify(sig, data, address):
    return VerifyMessage(address, BitcoinMessage(data), sig)

def pubkey_serialize(pubkey):
    return str(P2PKHBitcoinAddress.from_pubkey(pubkey))

# Register algorithm.
algo = bitjws.Algorithm('CUSTOM-BITCOIN-SIGN',
    sign=sign, verify=verify, pubkey_serialize=pubkey_serialize)
bitjws.ALGORITHM_AVAILABLE[algo.name] = algo

# bitjws expects privkey objects to contain a pubkey member.
key = CBitcoinSecret("L4vB5fomsK8L95wQ7GFzvErYGht49JsCPJyJMHpB4xGM6xgi2jvG")
key.pubkey = key.pub

# sign/verify using the algorithm registered.
ser = bitjws.sign_serialize(key, hello='world', algorithm_name=algo.name)
print(ser)
headers, payload = bitjws.validate_deserialize(ser, algorithm_name=algo.name)
print(headers, payload)
assert headers['kid'] == '1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G'
```


## Input/Output: single key


<table>
  <tr>
    <th>Key input</th>
    <th>Serialization output</th>
  </tr>

  <tr>
    <td><pre lang="python">import bitjws
rawkey = b'\x01' * 32
key = bitjws.PrivateKey(rawkey)</pre></td>
    <td><pre lang="python">ser = bitjws.sign_serialize(key, expire_after=None)</pre></td>
  </tr>

  <tr>
    <td></td>
    <td><sub>eyJhbGciOiAiQ1VTVE9NLUJJVENPSU4tU0lHTiIsICJraWQiOiAiMUM2UmM<br/>
zdzI1Vkh1ZDNkTERhbXV0YXFmS1dxaHJMUlRhRCIsICJ0eXAiOiAiSldUIn0.<br/>
<br/>
eyJhdWQiOiBudWxsLCAiZXhwIjogMjE0NzQ4MzY0OH0.<br/>
<br/>
SUptY1VJZXBrSllZMFpxS0FVcStNOUVjK0tWSitUUG13c0MrREMveXhOc0N<br/>
LRXIvbzJNd3NoMWRubGdsRnI0ZjdrSFQrZ1ZkL25IUkFRMEpDdGx6S0VjPQ</sub></td>
  </tr>

</table>


Line breaks were added in the serialization output, but none of those are present. There are three segments separated by ".": header, payload, and signature, respectively. The segments can be separated by performing `header, payload, signature = ser.split('.')`.

<table>
  <tr>
    <th>Raw header</th>
    <th>Decoded header</th>
  </tr>

  <tr>
    <td><sub>eyJhbGciOiAiQ1VTVE9NLUJJVENPSU4tU0lHTiIsICJraWQiOiAiMUM2UmMzdz<br/>
I1Vkh1ZDNkTERhbXV0YXFmS1dxaHJMUlRhRCIsICJ0eXAiOiAiSldUIn0</td>
    <td><pre lang="python">bitjws.base64url_decode(header.encode('utf8'))</pre></td>
  </tr>

  <tr>
    <td></td>
    <td><pre>{
  "alg": "CUSTOM-BITCOIN-SIGN",
  "kid": "1C6Rc3w25VHud3dLDamutaqfKWqhrLRTaD",
  "typ": "JWT"
}</pre></td>
  </tr>

</table>

<table>
  <tr>
    <th>Raw payload</th>
    <th>Decoded payload</th>
  </tr>

  <tr>
    <td><sub>eyJhdWQiOiBudWxsLCAiZXhwIjogMjE0NzQ4MzY0OH0</td>
    <td><pre lang="python">bitjws.base64url_decode(payload.encode('utf8'))</pre></td>
  </tr>

  <tr>
    <td></td>
    <td><pre>{
  "aud": null,
  "exp": 2147483648
}</pre></td>
  </tr>

</table>

<table>
  <tr>
    <th>Raw signature</th>
    <th>Decoded signature</th>
  </tr>

  <tr>
    <td><sub>SUptY1VJZXBrSllZMFpxS0FVcStNOUVjK0tWSitUUG13c0MrREMveXhOc0N<br/>
LRXIvbzJNd3NoMWRubGdsRnI0ZjdrSFQrZ1ZkL25IUkFRMEpDdGx6S0VjPQ</sub></td>
    <td><pre lang="python">bitjws.base64url_decode(
    signature.encode('utf8'))</pre></td>
  </tr>

  <tr>
    <td></td>
    <td><sub>IJmcUIepkJYY0ZqKAUq+M9Ec+KVJ+TPmwsC+DC/yxNs
CKEr/o2Mwsh1dnlglFr4f7kHT+gVd/nHRAQ0JCtlzKEc=</sub></td>
  </tr>

</table>

There is no actual line break in the decoded signature. The decoded signature is the base64 signature produced according to the Bitcoin message signing method.


## Input/Output: multisig

Using the same key from the previous section, running `bitjws.multisig_sign_serialize([key], expire_after=None)` resuts in the following output:

```
{
  "payload": "eyJhdWQiOiBudWxsLCAiZXhwIjogMjE0NzQ4MzY0OH0",
  "signatures": [
    {
      "signature": "SUptY1VJZXBrSllZMFpxS0FVcStNOUVjK0tWSitUUG13c0MrREMveXhOc0NLRXIvbzJNd3NoMWRubGdsRnI0ZjdrSFQrZ1ZkL25IUkFRMEpDdGx6S0VjPQ",
      "protected": "eyJhbGciOiAiQ1VTVE9NLUJJVENPSU4tU0lHTiIsICJraWQiOiAiMUM2UmMzdzI1Vkh1ZDNkTERhbXV0YXFmS1dxaHJMUlRhRCIsICJ0eXAiOiAiSldUIn0"
    }
  ]
}
```

This is a different format from the one used for single key signing. The format now is defined as "general JSON serialization" in the JWS spec, and is used to store a list of signatures and headers. The headers are stored in the "protected" fields, which means their values are integrity protected (i.e. the signature takes them into account). Decoding the values for `payload`, `signatures[0]["signature"]`, `signatures[0]["protected"]` is done using the same `bitjws.base64url_decode` function used earlier. The number of signatures corresponds to the number of keys passed to `bitjws.multisig_sign_serialize`.
