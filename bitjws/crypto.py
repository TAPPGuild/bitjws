import os
import base64
import hashlib
from struct import pack
from collections import namedtuple

from base58 import b58encode, b58decode
from secp256k1 import PublicKey, ALL_FLAGS

__all__ = ['Network', 'BC', 'gen_privatekey',
           'wif_to_privkey', 'privkey_to_wif']


BC_BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

Network = namedtuple("Network", "name wifprefix pubkeyprefix msgprefix")
BC = Network(name='bitcoin',
             wifprefix=b'\x80',
             pubkeyprefix=b'\x00',
             msgprefix=b'Bitcoin Signed Message:\n')


def varint(size):
    # Variable length integer encoding:
    # https://en.bitcoin.it/wiki/Protocol_documentation
    if size < 0xFD:
        return pack(b'<B', size)
    elif size <= 0xFFFF:
        return b'\xFD' + pack(b'<H', size)
    elif size <= 0xFFFFFFFF:
        return b'\xFE' + pack(b'<I', size)
    else:
        return b'\xFF' + pack(b'<Q', size)


def shasha(msg):
    """SHA256(SHA256(msg)) -> HASH object"""
    res = hashlib.sha256(hashlib.sha256(msg).digest())
    return res


def ripesha(msg):
    """RIPEMD160(SHA256(msg)) -> HASH object"""
    ripe = hashlib.new('ripemd160')
    ripe.update(hashlib.sha256(msg).digest())
    return ripe


def gen_privatekey():
    return os.urandom(32)


def privkey_to_wif(rawkey, compressed=True, net=BC):
    """Convert privkey bytes to Wallet Import Format (WIF)."""
    # See https://en.bitcoin.it/wiki/Wallet_import_format.
    k = net.wifprefix + rawkey
    if compressed:
        k += b'\x01'

    chksum = shasha(k).digest()[:4]
    key = k + chksum

    b58key = b58encode(key)
    return b58key


def wif_to_privkey(wif, compressed=True, net=BC):
    """Convert Wallet Import Format (WIF) to privkey bytes."""
    key = b58decode(wif)

    version, raw, check = key[0:1], key[1:-4], key[-4:]
    assert version == net.wifprefix, "unexpected version byte"

    check_compare = shasha(version + raw).digest()[:4]
    assert check_compare == check

    if compressed:
        raw = raw[:-1]

    return raw


def pubkey_to_addr(pubkey, net=BC):
    # Addresses:
    # https://en.bitcoin.it/wiki/Protocol_documentation
    keyhash = net.pubkeyprefix + ripesha(pubkey).digest()
    checksum = shasha(keyhash).digest()[:4]
    address = b58encode(keyhash + checksum)
    return address


def verify(base64sig, msg, address, ctx=None, net=BC):
    if len(base64sig) != 88:
        raise Exception("Invalid base64 signature length")

    msg = msg.encode('utf8')
    fullmsg = (varint(len(net.msgprefix)) + net.msgprefix +
               varint(len(msg)) + msg)
    hmsg = shasha(fullmsg).digest()

    sigbytes = base64.b64decode(base64sig)
    if len(sigbytes) != 65:
        raise Exception("Invalid signature length")

    compressed = (ord(sigbytes[0:1]) - 27) & 4 != 0
    rec_id = (ord(sigbytes[0:1]) - 27) & 3

    p = PublicKey(ctx=ctx, flags=ALL_FLAGS)
    sig = p.ecdsa_recoverable_deserialize(sigbytes[1:], rec_id)

    # Recover the ECDSA public key.
    recpub = p.ecdsa_recover(hmsg, sig, raw=True)
    pubser = PublicKey(recpub, ctx=ctx).serialize(compressed=compressed)

    addr = pubkey_to_addr(pubser, net)
    return addr == address


def sign(privkey, msg, compressed=True, net=BC):
    msg = msg.encode('utf8')
    fullmsg = (varint(len(net.msgprefix)) + net.msgprefix +
               varint(len(msg)) + msg)
    hmsg = shasha(fullmsg).digest()

    rawsig = privkey.ecdsa_sign_recoverable(hmsg, raw=True)
    sigbytes, recid = privkey.ecdsa_recoverable_serialize(rawsig)

    meta = 27 + recid
    if compressed:
        meta += 4

    res = base64.b64encode(chr(meta).encode('utf8') + sigbytes)
    return res
