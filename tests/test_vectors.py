import os
import json
import bitjws

HERE = os.path.dirname(os.path.abspath(__file__))

def test_vectors():
    tests = json.load(open(os.path.join(HERE, 'vectors.json')))
    for entry in tests:
        header, payload = bitjws.validate_deserialize(
            entry['jwsdata'], requrl=entry['aud'], check_expiration=False)
        assert header and payload
        assert header['kid'] == entry['kid']
        assert payload['aud'] == entry['aud']
