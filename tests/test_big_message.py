# This test exercises the varint function.
import os
import pytest
import bitjws

RUN_TOO_BIG = int(os.getenv('RUN_TOO_BIG', '0'))

rawkey = bitjws.gen_privatekey()

def test_slightly_big():
    key = bitjws.PrivateKey(rawkey)

    ser = bitjws.sign_serialize(key, test='a' * 254)
    h, p = bitjws.validate_deserialize(ser)
    assert h and p

def test_big():
    key = bitjws.PrivateKey(rawkey)

    ser = bitjws.sign_serialize(key, test='a' * 65536)
    h, p = bitjws.validate_deserialize(ser)
    assert h and p

def test_too_big():
    if not RUN_TOO_BIG:
        pytest.skip()
        return

    key = bitjws.PrivateKey(rawkey)

    try:
        ser = bitjws.sign_serialize(key, test='a' * 4294967295)
        h, p = bitjws.validate_deserialize(ser)
        assert h and p
    except MemoryError:
        pytest.skip('Not enough memory to run this test')
        return
