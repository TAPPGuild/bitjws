bitjws |Build Status| |Coverage Status|
=======================================

JWS (`JSON Web
Signature <http://self-issued.info/docs/draft-ietf-jose-json-web-signature.html>`__)
using Bitcoin message signing as the algorithm.

Install
-------

By default it's expected that
`secp256k1 <https://github.com/bitcoin/secp256k1>`__ is available, so
install it before proceeding; make sure to run
``./configure --enable-module-recovery``. If you're using some other
library that provides the functionality necessary for this, check the
**Using a custom library** section below.

bitjws can be installed by running ``pip install bitjws``.

Usage
-----

Use this package to produce signed JWS messages using the Bitcoin
message signing schema and to validate such messages. The JWS header
generated is the following one:

.. code:: json

    {
      "typ": "JWT",
      "alg": "CUSTOM-BITCOIN-SIGN",
      "kid": <bitcoin_address>
    }

where "kid" is used to indicate the public part of the key used during
signing.

Sign a message
~~~~~~~~~~~~~~

.. code:: python

    import bitjws

    mykey = bitjws.PrivateKey()
    data = bitjws.sign_serialize(mykey)

``sign_serialize`` function definition:

.. code:: python

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

Validate a message
~~~~~~~~~~~~~~~~~~

.. code:: python

    import bitjws

    header, payload = bitjws.validate_deserialize(data)

``validate_deserialize`` may raise ``bitjws.InvalidMessage`` or
``bitwjs.InvalidPayload``. Function definition:

.. code:: python

    def validate_deserialize(rawmsg, requrl=None, check_expiration=True):
        """
        Validate a JWT compact serialization and return the header and
        payload if the signature is good.

        If check_expiration is False, the payload will be accepted even if
        expired.
        """

Multiple signatures
~~~~~~~~~~~~~~~~~~~

.. code:: python

    import bitjws

    key1 = bitjws.PrivateKey()
    key2 = bitjws.PrivateKey()

    data = bitjws.multisig_sign_serialize([key1, key2])
    headers, payload = bitjws.multisig_validate_deserialize(data)

The other parameters accepted by ``multisig_sign_serialize`` and
``multisig_validate_deserialize`` are the same as described for
``sign_serialize`` and ``validate_deserialize``. The data returned and
passed to the validate function are different, as the multisig functions
use the format described as general JSON serialization in the JWS spec.

Utilities and other functionality
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Check ``tests/`` and ``example/`` for other functions available but not
documented above.

Using a custom library
----------------------

It's possible to use ``bitjws`` without the ``secp256k1`` library, as
well with other signing algorithms.

To install ``bitjws`` without ``secp256k1``, use:

::

    pip install bitjws --no-deps
    pip install base58

Custom signing/validation
~~~~~~~~~~~~~~~~~~~~~~~~~

``bitjws`` allows custom algorithms to be registered. They are used
during signing/validation and are assumed to be an instance of
``bitjws.Algorithm``.

First define a new implementation:

.. code:: python

    algorithm = bitjws.Algorithm(name,
        sign=sign_function,
        verify=verify_function,
        pubkey_serialize=pubkey_serialize_function)

And then register it:

.. code:: python

    bitjws.ALGORITHM_AVAILABLE[algorithm.name] = algorithm

To successfully use this algorithm, the following expectations must be
met:

-  ``sign_function`` takes a private key and data to be signed and
   returns bytes.
-  ``verify_function`` takes a signature, the original data, and an
   address (the Bitcoin address or something equivalent for another
   implementation, like a public key) and returns a boolean (True if
   verification is successfull, False otherwise).
-  The ``pubkey_serialize_function`` function takes a single parameter
   (e.g. a public key) and returns text (e.g. a bitcoin address).
-  The private key has a member named ``pubkey``.

Now it's possible to call the sign/validate functions with the parameter
``algorithm_name=algorithm.name``.

Example of custom implementation using python-bitcoinlib
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run ``pip install python-bitcoinlib`` if you don't have this custom
dependency installed. The following snippet registers a new algorithm as
mentioned above and uses a sample key for a complete example.

.. code:: python

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

.. |Build Status| image:: https://travis-ci.org/g-p-g/bitjws.svg?branch=master
   :target: https://travis-ci.org/g-p-g/bitjws
.. |Coverage Status| image:: https://coveralls.io/repos/g-p-g/bitjws/badge.svg?branch=master&service=github
   :target: https://coveralls.io/github/g-p-g/bitjws?branch=master
