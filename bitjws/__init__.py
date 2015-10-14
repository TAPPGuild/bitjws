from .jws import (ALGORITHM_AVAILABLE, Algorithm,
                  InvalidMessage, InvalidPayload, base64url_decode,
                  base64url_encode, sign_serialize, validate_deserialize,
                  multisig_sign_serialize, multisig_validate_deserialize)

try:
    from .crypto import (gen_privatekey, wif_to_privkey, privkey_to_wif,
                         pubkey_to_addr)
    from secp256k1 import PrivateKey, PublicKey
except ImportError as err:
    import sys
    sys.stderr.write("ERROR: secp256k1 not available.\n{}\n".format(err))
