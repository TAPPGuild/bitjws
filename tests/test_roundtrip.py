import json
import bitjws

def test_encode_decode():
    key = bitjws.PrivateKey()

    ser = bitjws.sign_serialize(key)
    header, payload = bitjws.validate_deserialize(ser)

    rawheader, rawpayload = ser.rsplit('.', 1)[0].split('.')
    origheader = bitjws.base64url_decode(rawheader.encode('utf8'))
    origpayload = bitjws.base64url_decode(rawpayload.encode('utf8'))

    assert header == json.loads(origheader.decode('utf8'))
    assert payload == json.loads(origpayload.decode('utf8'))

def test_audience():
    key = bitjws.PrivateKey()

    ser = bitjws.sign_serialize(key, requrl='https://example.com/api/login')
    header, payload = bitjws.validate_deserialize(
        ser, requrl='https://example.com/api/login')
    assert header is not None
    assert payload is not None
