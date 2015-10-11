# bitjws [![Build Status](https://travis-ci.org/g-p-g/bitjws.svg?branch=master)](https://travis-ci.org/g-p-g/bitjws) [![Coverage Status](https://coveralls.io/repos/g-p-g/bitjws/badge.svg?branch=master&service=github)](https://coveralls.io/github/g-p-g/bitjws?branch=master)
JWS using Bitcoin message signing.


## Install

Install [secp256k1](https://github.com/bitcoin/secp256k1) before proceeding; make sure to run `./configure --enable-module-recovery`.

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
    if received after current_time + expire_after.

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


##### Utilities and other functionality

Check `tests/` and `example/` for other functions available but not documented above.
