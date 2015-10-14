import pytest
import bitjws

def test_dummy_algo():
    key = bitjws.PrivateKey()

    # Setup a new algorithm for signing/verifying.
    # The sign function always take two parameters and return bytes.
    # The verify function always take three parameters and return a boolean.
    # The pubkey_serialize function take a pubkey object and return text.
    newalgo = bitjws.Algorithm('dummy',
        sign=lambda privkey, signdata: signdata.encode('utf8'),
        verify=lambda sig, data, pubkey: True,
        pubkey_serialize=lambda x: "hello")
    bitjws.ALGORITHM_AVAILABLE[newalgo.name] = newalgo

    ser = bitjws.sign_serialize(key)
    with pytest.raises(bitjws.InvalidMessage):
        # Algorithm mismatch.
        bitjws.validate_deserialize(ser, algorithm_name='dummy')

    ser = bitjws.sign_serialize(key, algorithm_name='dummy')
    with pytest.raises(bitjws.InvalidMessage):
        # Algorithm mismatch.
        bitjws.validate_deserialize(ser)

    result = bitjws.validate_deserialize(ser, algorithm_name='dummy')
    assert result[0] and result[1]

def test_none_algo():
    # Register an algorithm named None.
    newalgo = bitjws.Algorithm(None,
        sign=lambda a, b: b.encode('utf8'),
        verify=lambda a, b, c: True,
        pubkey_serialize=lambda x: "hello")
    bitjws.ALGORITHM_AVAILABLE[None] = newalgo

    key = bitjws.PrivateKey()
    ser = bitjws.sign_serialize(key, algorithm_name=None)

    with pytest.raises(bitjws.InvalidMessage):
        # Although it "signs" a message, decoding does complete
        # due to its name (None).
        bitjws.validate_deserialize(ser, algorithm_name=None)
    with pytest.raises(bitjws.InvalidMessage):
        # The algorithm name (None) is defined in the header, so it
        # fails to decode here too.
        bitjws.validate_deserialize(ser)
