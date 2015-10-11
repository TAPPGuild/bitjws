import pytest
from bitjws import PrivateKey, crypto, gen_privatekey

def test_verify():
    address = "1Jz43WvRgwRdvDzezbWdcSBfUuHSqtMSVx"

    b64sig = b"IG40ewesu5qbKQ/exb2EzRwtuNQZ3qW1F8dIebXx1kyYNV7zATw3RE2BvAcuEer60UlczU5Z2lJOdWRV9x0nPu4="
    msg = "test"
    assert crypto.verify(b64sig, msg, address)

    b64sig = b"HwLwlzQQ/d4MM4hoi4a6QI8VffNKTmJaAyQR/QEcZAe8tyZGeCIBblkI+BPqWB81IzD4Iquc7DnB905Cn06gGZ0="
    msg = "test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test"
    assert crypto.verify(b64sig, msg, address)

def test_badkey():
    key = gen_privatekey()
    with pytest.raises(TypeError):
        PrivateKey(key[:-1])
