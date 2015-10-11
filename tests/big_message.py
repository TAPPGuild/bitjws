import os
import pytest
import bitjws

rawkey = bitjws.gen_privatekey()

def test_too_big():
    key = bitjws.PrivateKey(rawkey)

    try:
        ser = bitjws.sign_serialize(key, test='a' * 4294967295)
        h, p = bitjws.validate_deserialize(ser)
        assert h and p
    except MemoryError:
        pytest.skip('Not enough memory to run this test')
        return
