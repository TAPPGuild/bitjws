import json
import pytest
import bitjws

def test_encode_decode():
    key1 = bitjws.PrivateKey()
    pubkey1 = bitjws.pubkey_to_addr(key1.pubkey.serialize())
    key2 = bitjws.PrivateKey()
    pubkey2 = bitjws.pubkey_to_addr(key2.pubkey.serialize())

    ser = bitjws.multisig_sign_serialize([key1, key2])
    headers, payload = bitjws.multisig_validate_deserialize(ser)

    rawpayload = json.loads(ser)['payload']
    origpayload = bitjws.base64url_decode(rawpayload.encode('utf8'))

    keys_found = {pubkey1: False, pubkey2: False}
    assert len(headers) == 2
    for h in headers:
        assert len(h) == 3
        assert h['typ'] == 'JWT'
        assert h['alg'] == 'CUSTOM-BITCOIN-SIGN'
        assert h['kid'] in keys_found
        assert keys_found[h['kid']] == False
        keys_found[h['kid']] = True
    assert all(keys_found.values())

    assert isinstance(payload.get('exp', ''), (float, int))
    assert payload['aud'] is None
    assert len(payload) == 2
    assert payload == json.loads(origpayload.decode('utf8'))

def test_payload_nojson():
    key = bitjws.PrivateKey()

    # Use a payload that is not JSON encoded.
    ser = json.loads(bitjws.multisig_sign_serialize([key]))
    ser['payload'] = bitjws.base64url_encode(b'test').decode('utf8')

    # Sign the new payload.
    signdata = '{}.{}'.format(ser['signatures'][0]['protected'], ser['payload'])
    sig = bitjws.ALGORITHM_AVAILABLE['CUSTOM-BITCOIN-SIGN'].sign(
        key, signdata)
    sig64 = bitjws.base64url_encode(sig).decode('utf8')
    ser['signatures'][0]['signature'] = sig64

    serenc = json.dumps(ser)
    with pytest.raises(bitjws.InvalidMessage):
        # The new payload was not JSON encoded, so it cannot be
        # decoded as that.
        bitjws.multisig_validate_deserialize(serenc)
    # But we can get its raw value.
    headers, payload = bitjws.multisig_validate_deserialize(serenc,
        decode_payload=False)

    assert len(headers) == 1
    assert payload == b'test'
