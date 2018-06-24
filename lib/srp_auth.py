import hmac

import srp

from hashlib import sha256
from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def get_ukey(username, salt, ckey):
    h = hmac.new(ckey, digestmod=sha256)
    h.update(username)
    h.update(salt)
    return h.digest()


def _get_challenge_key(M, request_id, ukey):
    h = hmac.new(ukey, digestmod=sha256)
    h.update(M)
    h.update(request_id.to_bytes(4, byteorder="big"))
    return h.digest()


def get_challenge(request_id, client_seed, username, salt, vkey, ukey):
    verifier = srp.Verifier(username, salt, vkey, client_seed,
                            hash_alg=srp.SHA256, ng_type=srp.NG_2048)

    nonce = urandom(12)
    key = _get_challenge_key(verifier.M, request_id, ukey)
    token = nonce + AESGCM(key).encrypt(nonce,
                                        verifier.get_ephemeral_secret(), username)
    _, server_seed = verifier.get_challenge()
    return (server_seed, token)


def _decrypt_token(M, request_id, ukey):
    h = hmac.new(ukey, digestmod=sha256)
    h.update(M)
    h.update(request_id.to_bytes(4, byteorder="big"))
    return h.digest()


def verify_challenge(request_id, proof, client_seed, token, username, salt, vkey, ukey):
    nonce = token[0:12]
    token = token[12:]
    key = _get_challenge_key(proof, request_id, ukey)
    try:
        secret = AESGCM(key).decrypt(nonce, token, username)
    except InvalidTag:
        return None
    verifier = srp.Verifier(username, salt, vkey, client_seed,
                            bytes_b=secret, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    verifier.verify_session(proof)
    return verifier.get_session_key()
