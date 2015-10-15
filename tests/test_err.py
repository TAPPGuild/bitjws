import json
import time
import bitjws
import pytest

def _encode_header(newheader, origraw):
    mod = bitjws.base64url_encode(json.dumps(newheader).encode('utf8'))
    result = mod.decode('utf8') + origraw[origraw.find('.'):]
    return result

def test_payload_expired():
    key = bitjws.PrivateKey()
    print(bitjws.privkey_to_wif(key.private_key))

    # expire_after must be greater than 0 or None.
    with pytest.raises(bitjws.jws.InvalidPayload):
        bitjws.sign_serialize(key, expire_after=0)

    ser = bitjws.sign_serialize(key, expire_after=0.01)
    time.sleep(0.02)
    with pytest.raises(bitjws.jws.InvalidPayload):
        # payload expired.
        bitjws.validate_deserialize(ser)

    # But the signature can still be verified and the msg decoded
    # if expiration checks are disabled.
    h, p = bitjws.validate_deserialize(ser, check_expiration=False)
    assert h and p

    # Check with multisig.
    ser = bitjws.multisig_sign_serialize([key], expire_after=0.01)
    time.sleep(0.02)
    with pytest.raises(bitjws.jws.InvalidPayload):
        # payload expired.
        bitjws.multisig_validate_deserialize(ser)

def test_invalid_audience():
    key = bitjws.PrivateKey()
    print(bitjws.privkey_to_wif(key.private_key))

    ser = bitjws.sign_serialize(key, requrl='https://example.com/api/login')

    with pytest.raises(bitjws.jws.InvalidPayload):
        # audience not specified.
        bitjws.validate_deserialize(ser)
    with pytest.raises(bitjws.jws.InvalidPayload):
        # audience does not match.
        bitjws.validate_deserialize(ser, requrl='https://example.com/api')

def test_invalid_header():
    key = bitjws.PrivateKey()
    print(bitjws.privkey_to_wif(key.private_key))

    ser = bitjws.sign_serialize(key)
    # Decode header.
    rawheader = ser.split('.')[0]
    origheader = bitjws.base64url_decode(rawheader.encode('utf8'))
    header = json.loads(origheader.decode('utf8'))

    # Modify the algorithm specified (by removing it).
    algorithm = header.pop('alg')

    # Encode header and try to deserialize.
    ser = _encode_header(header, ser)
    with pytest.raises(bitjws.jws.InvalidMessage):
        # Unknown algorithm.
        bitjws.validate_deserialize(ser)

    # Set some other algorithm.
    header['alg'] = 'SHA256'
    ser = _encode_header(header, ser)
    with pytest.raises(bitjws.jws.InvalidMessage):
        # Unknown algorithm.
        bitjws.validate_deserialize(ser)

    # Drop the key used to sign.
    header['alg'] = algorithm
    kid = header.pop('kid')
    ser = _encode_header(header, ser)
    with pytest.raises(bitjws.jws.InvalidMessage):
        # No address specified.
        bitjws.validate_deserialize(ser)

    # Try to decode the original one.
    ser = rawheader + '.' + ser.split('.', 1)[1]
    header, payload = bitjws.validate_deserialize(ser)
    assert header is not None
    assert payload is not None
    h, p = bitjws.validate_deserialize(ser, check_expiration=False)
    assert h == header
    assert p == payload


def test_malformed():
    key = bitjws.PrivateKey()
    print(bitjws.privkey_to_wif(key.private_key))

    ser = bitjws.sign_serialize(key)
    # Drop one of the segments.
    ser = ser.split('.', 1)[1]
    with pytest.raises(bitjws.jws.InvalidMessage):
        bitjws.validate_deserialize(ser)

    # Add an empty segment.
    ser = '.' + ser
    with pytest.raises(bitjws.jws.InvalidMessage):
        bitjws.validate_deserialize(ser)

    # Add an invalid segment.
    ser = ' ' + ser
    with pytest.raises(bitjws.jws.InvalidMessage):
        # This will fail while trying to parse it as JSON.
        bitjws.validate_deserialize(ser)

def test_invalid_signature_key():
    key = bitjws.PrivateKey()
    print(bitjws.privkey_to_wif(key.private_key))

    ser = bitjws.sign_serialize(key)
    # Decode header.
    rawheader = ser.rsplit('.')[0]
    origheader = bitjws.base64url_decode(rawheader.encode('utf8'))
    header = json.loads(origheader.decode('utf8'))

    # Modify the key declared to be used in the signature.
    header['kid'] = '123'
    ser = _encode_header(header, ser)
    header, payload = bitjws.validate_deserialize(ser)
    # If both header or payload are None then it failed to validate
    # the signature (as expected).
    assert header is None
    assert payload is None

def test_bad_signature():
    wif = 'L2Ai1TBwKfyPshmqosKRBvJ47qUCDKesfZXh2zLoYoB7NHgdPS6d'
    key = bitjws.PrivateKey(bitjws.wif_to_privkey(wif))
    assert bitjws.privkey_to_wif(key.private_key) == wif

    ser = bitjws.sign_serialize(key)
    # Drop the last byte from the signature.
    ser = ser[:-1]
    with pytest.raises(bitjws.jws.InvalidMessage):
        # It will fail to decode as base64 due to padding.
        bitjws.validate_deserialize(ser)
    # Drop another byte.
    ser = ser[:-1]
    with pytest.raises(bitjws.jws.InvalidMessage):
        # Although it can be decoded now, the length is incorrect.
        bitjws.validate_deserialize(ser)

    # Replace the signature by something that has the correct
    # length before decoding but becomes invalid after it.
    dummy = bitjws.base64url_encode(b'a' * 88)
    ser = ser[:ser.rfind('.')] + '.' + dummy.decode('utf8')
    with pytest.raises(bitjws.jws.InvalidMessage):
        # Now it fails because the dummy signature above produces
        # 66 bytes (instead of 65) after being decoded.
        bitjws.validate_deserialize(ser)

def test_multisig_missingkeys():
    key = bitjws.PrivateKey()

    ser = bitjws.multisig_sign_serialize([key])
    # This should work.
    headers, payload = bitjws.multisig_validate_deserialize(ser)
    assert len(headers) == 1 and payload

    serobj = json.loads(ser)

    payload = serobj.pop('payload')
    ser = json.dumps(serobj)
    with pytest.raises(bitjws.jws.InvalidMessage):
        # Key 'payload' is missing.
        bitjws.multisig_validate_deserialize(ser)

    serobj['payload'] = payload
    signatures = serobj.pop('signatures')
    ser = json.dumps(serobj)
    with pytest.raises(bitjws.jws.InvalidMessage):
        # Key 'signatures' is missing.
        bitjws.multisig_validate_deserialize(ser)

    serobj['signatures'] = 'hello'
    ser = json.dumps(serobj)
    with pytest.raises(bitjws.jws.InvalidMessage):
        # 'signatures' is not a list.
        bitjws.multisig_validate_deserialize(ser)

    del serobj['signatures']
    del serobj['payload']
    ser = json.dumps(serobj)
    with pytest.raises(bitjws.jws.InvalidMessage):
        bitjws.multisig_validate_deserialize(ser)

    # Remove a key from one of the signatures.
    serobj['signatures'] = signatures
    serobj['payload'] = payload
    sig0 = serobj['signatures'][0].copy()

    del serobj['signatures'][0]['protected']
    ser = json.dumps(serobj)
    with pytest.raises(bitjws.jws.InvalidMessage):
        # data['signatures'][0]['protected'] is missing
        bitjws.multisig_validate_deserialize(ser)

    serobj['signatures'][0] = sig0.copy()
    del serobj['signatures'][0]['signature']
    ser = json.dumps(serobj)
    with pytest.raises(bitjws.jws.InvalidMessage):
        # data['signatures'][0]['signture'] is missing
        bitjws.multisig_validate_deserialize(ser)

    # Remove the only signature entry.
    serobj['signatures'].pop()
    ser = json.dumps(serobj)
    with pytest.raises(bitjws.jws.InvalidMessage):
        # No signatures.
        bitjws.multisig_validate_deserialize(ser)

def test_multisig_invalidsig():
    key = bitjws.PrivateKey()

    ser = bitjws.multisig_sign_serialize([key])
    assert all(bitjws.multisig_validate_deserialize(ser))

    serobj = json.loads(ser)
    dummy = bitjws.base64url_encode(b'a' * 88)
    serobj['signatures'][0]['signature'] = dummy.decode('utf8')

    ser = json.dumps(serobj)
    with pytest.raises(bitjws.jws.InvalidMessage):
        # Invalid signature length.
        bitjws.multisig_validate_deserialize(ser)

def test_multisig_partiallyinvalid():
    key1 = bitjws.PrivateKey()
    key2 = bitjws.PrivateKey()
    key3 = bitjws.PrivateKey()

    ser = bitjws.multisig_sign_serialize([key1, key2, key3])
    assert all(bitjws.multisig_validate_deserialize(ser))

    serobj = json.loads(ser)
    # Swap signatures.
    sig0 = serobj['signatures'][0]['signature']
    sig1 = serobj['signatures'][1]['signature']
    sig0, sig1 = sig1, sig0
    serobj['signatures'][0]['signature'] = sig0
    serobj['signatures'][1]['signature'] = sig1

    ser = json.dumps(serobj)
    headers, payload = bitjws.multisig_validate_deserialize(ser)
    assert headers is None
    assert payload is None

def test_invalid_algorithm():
    key1 = bitjws.PrivateKey()

    # Invalid algorithm name for signing.
    with pytest.raises(AssertionError):
        bitjws.sign_serialize(key1, algorithm_name='test')
    with pytest.raises(AssertionError):
        bitjws.multisig_sign_serialize([key1], algorithm_name='test')

    # Invalid algorithm name for verifying.
    ser = bitjws.sign_serialize(key1)
    with pytest.raises(AssertionError):
        bitjws.validate_deserialize(ser, algorithm_name='test')
    ser = bitjws.multisig_sign_serialize([key1])
    with pytest.raises(AssertionError):
        bitjws.multisig_validate_deserialize(ser, algorithm_name='test')
