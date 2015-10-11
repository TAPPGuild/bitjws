import json
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
