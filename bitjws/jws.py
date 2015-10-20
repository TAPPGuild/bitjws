import json
import time
import base64
from collections import namedtuple

try:
    from . import crypto
except ImportError:
    crypto = None

__all__ = ['ALGORITHM_AVAILABLE', 'Algorithm',
           'InvalidMessage', 'InvalidPayload', 'base64url_decode',
           'base64url_encode', 'sign_serialize', 'validate_deserialize',
           'multisig_sign_serialize', 'multisig_validate_deserialize']


Algorithm = namedtuple('Algorithm', 'name sign verify pubkey_serialize')

ALGORITHM_AVAILABLE = {}

if crypto:
    DEFAULT_ALGO = ALGO_BITCOIN_SIGN = 'CUSTOM-BITCOIN-SIGN'
    CustomBitcoinSign = Algorithm(
        name=ALGO_BITCOIN_SIGN,
        sign=crypto.sign,
        verify=crypto.verify,
        pubkey_serialize=lambda pub: crypto.pubkey_to_addr(pub.serialize())
    )

    ALGORITHM_AVAILABLE[ALGO_BITCOIN_SIGN] = CustomBitcoinSign
else:
    DEFAULT_ALGO = None

TS2038 = 2 ** 31


class InvalidMessage(TypeError):
    """The JWT message is invalid. This might happen due to invalid
    segment count, bad segment encoding, bad signature encoding,
    missing/invalid algorithm, or missing signing key."""
    pass


class InvalidPayload(Exception):
    """Payload has expired or its audience does not match the expected one."""
    pass


def base64url_decode(msg):
    """
    Decode a base64 message based on JWT spec, Appendix B.
    "Notes on implementing base64url encoding without padding"
    """
    rem = len(msg) % 4
    if rem:
        msg += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(msg)


def base64url_encode(msg):
    """
    Encode a message to base64 based on JWT spec, Appendix B.
    "Notes on implementing base64url encoding without padding"
    """
    normalb64 = base64.urlsafe_b64encode(msg)
    return normalb64.rstrip(b'=')


def _jws_header(keyid, algorithm):
    """Produce a base64-encoded JWS header."""
    data = {
        'typ': 'JWT',
        'alg': algorithm.name,
        # 'kid' is used to indicate the public part of the key
        # used during signing.
        'kid': keyid
    }

    datajson = json.dumps(data, sort_keys=True).encode('utf8')
    return base64url_encode(datajson)


def _jws_payload(expire_at, requrl=None, **kwargs):
    """
    Produce a base64-encoded JWS payload.

    expire_at, if specified, must be a number that indicates
    a timestamp after which the message must be rejected.

    requrl, if specified, is used as the "audience" according
    to the JWT spec.

    Any other parameters are passed as is to the payload.
    """
    data = {
        'exp': expire_at,
        'aud': requrl
    }
    data.update(kwargs)

    datajson = json.dumps(data, sort_keys=True).encode('utf8')
    return base64url_encode(datajson)


def _jws_signature(signdata, privkey, algorithm):
    """
    Produce a base64-encoded JWS signature based on the signdata
    specified, the privkey instance, and the algorithm passed.
    """
    signature = algorithm.sign(privkey, signdata)
    return base64url_encode(signature)


def sign_serialize(privkey, expire_after=3600, requrl=None,
                   algorithm_name=DEFAULT_ALGO, **kwargs):
    """
    Produce a JWT compact serialization by generating a header, payload,
    and signature using the privkey and algorithm specified.

    The privkey object must contain at least a member named pubkey.

    The parameter expire_after is used by the server to reject the payload
    if received after current_time + expire_after. Set it to None to disable
    its use.

    The parameter requrl is optionally used by the server to reject the
    payload if it is not delivered to the proper place, e.g. if requrl
    is set to https://example.com/api/login but sent to a different server
    or path then the receiving server should reject it.

    Any other parameters are passed as is to the payload.
    """
    assert algorithm_name in ALGORITHM_AVAILABLE

    algo = ALGORITHM_AVAILABLE[algorithm_name]
    addy = algo.pubkey_serialize(privkey.pubkey)

    header = _jws_header(addy, algo).decode('utf8')
    payload = _build_payload(expire_after, requrl, **kwargs)
    signdata = "{}.{}".format(header, payload)
    signature = _jws_signature(signdata, privkey, algo).decode('utf8')

    return "{}.{}".format(signdata, signature)


def multisig_sign_serialize(privkeys, expire_after=3600, requrl=None,
                            algorithm_name=DEFAULT_ALGO, **kwargs):
    """
    Produce a general JSON serialization by generating a header, payload,
    and multiple signatures using the list of private keys specified.
    All the signatures will be performed using the same algorithm.

    The parameter expire_after is used by the server to reject the payload
    if received after current_time + expire_after. Set it to None to disable
    its use.

    The parameter requrl is optionally used by the server to reject the
    payload if it is not delivered to the proper place, e.g. if requrl
    is set to https://example.com/api/login but sent to a different server
    or path then the receiving server should reject it.

    Any other parameters are passed as is to the payload.
    """
    assert algorithm_name in ALGORITHM_AVAILABLE

    payload = _build_payload(expire_after, requrl, **kwargs)
    result = {"payload": payload, "signatures": []}
    algo = ALGORITHM_AVAILABLE[algorithm_name]

    for pk in privkeys:
        addy = algo.pubkey_serialize(pk.pubkey)
        header = _jws_header(addy, algo).decode('utf8')
        signdata = "{}.{}".format(header, payload)
        signature = _jws_signature(signdata, pk, algo).decode('utf8')
        result["signatures"].append({
            "protected": header,
            "signature": signature})

    return json.dumps(result)


def multisig_validate_deserialize(rawmsg, requrl=None, check_expiration=True,
                                  algorithm_name=DEFAULT_ALGO):
    """
    Validate a general JSON serialization and return the headers and
    payload if all the signatures are good.

    If check_expiration is False, the payload will be accepted even if
    expired.
    """
    assert algorithm_name in ALGORITHM_AVAILABLE

    algo = ALGORITHM_AVAILABLE[algorithm_name]

    data = json.loads(rawmsg)
    payload64 = data.get('payload', None)
    signatures = data.get('signatures', None)
    if payload64 is None or not isinstance(signatures, list):
        raise InvalidMessage('must contain "payload" and "signatures"')
    if not len(signatures):
        raise InvalidMessage('no signatures')

    try:
        payload, sigs = _multisig_decode(payload64, signatures)
    except Exception as err:
        raise InvalidMessage(str(err))

    all_valid = True
    try:
        for entry in sigs:
            valid = _verify_signature(algorithm=algo, **entry)
            all_valid = all_valid and valid
    except Exception as err:
        raise InvalidMessage('failed to verify signature: {}'.format(err))

    if not all_valid:
        return None, None

    _verify_payload(payload, check_expiration, requrl)
    return [entry['header'] for entry in sigs], payload


def validate_deserialize(rawmsg, requrl=None, check_expiration=True,
                         algorithm_name=DEFAULT_ALGO):
    """
    Validate a JWT compact serialization and return the header and
    payload if the signature is good.

    If check_expiration is False, the payload will be accepted even if
    expired.
    """
    assert algorithm_name in ALGORITHM_AVAILABLE
    algo = ALGORITHM_AVAILABLE[algorithm_name]

    segments = rawmsg.split('.')
    if len(segments) != 3 or not all(segments):
        raise InvalidMessage('must contain 3 non-empty segments')

    header64, payload64, cryptoseg64 = segments
    try:
        signature = base64url_decode(cryptoseg64.encode('utf8'))
        payload_data = base64url_decode(payload64.encode('utf8'))
        header_data = base64url_decode(header64.encode('utf8'))
        header = json.loads(header_data.decode('utf8'))
        payload = json.loads(payload_data.decode('utf8'))
    except Exception as err:
        raise InvalidMessage(str(err))

    try:
        valid = _verify_signature(
            '{}.{}'.format(header64, payload64),
            header,
            signature,
            algo)
    except Exception as err:
        raise InvalidMessage('failed to verify signature: {}'.format(err))

    if valid:
        _verify_payload(payload, check_expiration, requrl)
        return header, payload
    else:
        return None, None


def _verify_signature(data, header, signature, algorithm):
    alg = header.get('alg', None)
    if alg is None:
        raise InvalidMessage('no algorithm defined')
    if alg != algorithm.name:
        raise InvalidMessage('expected algorithm {}, received {}'.format(
            alg, algorithm.name))

    address = header.get('kid', '')
    if not address:
        raise InvalidMessage('no address specified (kid)')

    return algorithm.verify(signature, data, address)


def _verify_payload(payload, check_expiration, url=None):
    if check_expiration and payload.get('exp', 0) - time.time() < 0:
        raise InvalidPayload('payload expired')

    audience = payload.get('aud', None)
    if audience != url:
        raise InvalidPayload('audience does not match ({} != {})'.format(
            url, audience))


def _multisig_decode(payload64, signatures):
    payload_data = base64url_decode(payload64.encode('utf8'))
    payload = json.loads(payload_data.decode('utf8'))
    sigs = []

    for entry in signatures:
        header64 = entry.get('protected', None)
        cryptoseg64 = entry.get('signature', None)
        if header64 is None or cryptoseg64 is None:
            raise InvalidMessage('all signatures must contain "protected"'
                                 ' and "signature"')
        signature = base64url_decode(cryptoseg64.encode('utf8'))
        header_data = base64url_decode(header64.encode('utf8'))
        header = json.loads(header_data.decode('utf8'))
        sigs.append({
            'data': '{}.{}'.format(header64, payload64),
            'header': header,
            'signature': signature
        })

    return payload, sigs


def _build_payload(expire_after, requrl, **kwargs):
    if expire_after is not None:
        if expire_after <= 0:
            raise InvalidPayload("expire_after must be greater than 0 or None")
        expire_at = time.time() + expire_after
    else:
        expire_at = TS2038

    payload = _jws_payload(expire_at, requrl, **kwargs).decode('utf8')
    return payload
