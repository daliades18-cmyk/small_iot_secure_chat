# ================================
# FILE: crypto_utils.py
# ================================

import os
import json
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives.asymmetric import utils
# ==========================================
# RSA KEY GENERATION
# ==========================================
def generate_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_bytes, public_bytes


def load_private_key(private_bytes):
    return serialization.load_pem_private_key(
        private_bytes,
        password=None
    )


def load_public_key(public_bytes):
    return serialization.load_pem_public_key(
        public_bytes
    )


# ==========================================
# AES GCM ENCRYPTION
# ==========================================
def aes_encrypt(message_bytes, aes_key):

    nonce = os.urandom(12)

    aesgcm = AESGCM(aes_key)

    ciphertext = aesgcm.encrypt(
        nonce,
        message_bytes,
        None
    )

    return nonce, ciphertext


def aes_decrypt(nonce, ciphertext, aes_key):

    aesgcm = AESGCM(aes_key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext


# ==========================================
# HYBRID ENCRYPTION
# ==========================================
def hybrid_encrypt(message, receiver_public_key_bytes):

    receiver_public_key = load_public_key(
        receiver_public_key_bytes
    )

    aes_key = os.urandom(32)

    nonce, ciphertext = aes_encrypt(
        message.encode(),
        aes_key
    )

    encrypted_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key, nonce, ciphertext


def hybrid_decrypt(
        encrypted_key,
        nonce,
        ciphertext,
        receiver_private_key_bytes
):

    private_key = load_private_key(
        receiver_private_key_bytes
    )

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    plaintext = aes_decrypt(
        nonce,
        ciphertext,
        aes_key
    )

    return plaintext.decode()

# ==========================================
# DIGITAL SIGNATURES
# ==========================================
def sign_message(
        message_bytes,
        private_key_bytes
):

    private_key = load_private_key(
        private_key_bytes
    )

    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(
        message_bytes,
        signature,
        public_key_bytes
):

    public_key = load_public_key(
        public_key_bytes
    )

    try:

        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except Exception:

        return False
# ==========================================
# SERIALIZATION
# ==========================================
def serialize_message(
        encrypted_key,
        nonce,
        ciphertext,
        signature=b''
):

    data = {

        "key": base64.b64encode(
            encrypted_key
        ).decode(),

        "nonce": base64.b64encode(
            nonce
        ).decode(),

        "ciphertext": base64.b64encode(
            ciphertext
        ).decode(),

        "signature": base64.b64encode(
            signature
        ).decode()
    }

    json_data = json.dumps(
        data
    ).encode()

    length = len(
        json_data
    )

    return (
        length.to_bytes(4, 'big')
        + json_data
    )

def receive_exact(sock, size):

    data = b''

    while len(data) < size:

        packet = sock.recv(
            size - len(data)
        )

        if not packet:
            return None

        data += packet

    return data


def deserialize_message(sock):

    length_bytes = receive_exact(
        sock,
        4
    )

    if not length_bytes:
        return None

    length = int.from_bytes(
        length_bytes,
        'big'
    )

    json_data = receive_exact(
        sock,
        length
    )

    data = json.loads(
        json_data.decode()
    )

    encrypted_key = base64.b64decode(
        data["key"]
    )

    nonce = base64.b64decode(
        data["nonce"]
    )

    ciphertext = base64.b64decode(
        data["ciphertext"]
    )

    signature = base64.b64decode(
        data["signature"]
    )

    return (
        encrypted_key,
        nonce,
        ciphertext,
        signature
    )