from os import urandom
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


def generate_symmetric_keys() -> tuple:
    key = urandom(32)
    nonce = urandom(16)
    return key, nonce


def encrypt_symmetric(text: bytes, key: bytes, nonce: bytes) -> bytes:
    padder = padding.ANSIX923(64).padder()
    padded_text = padder.update(text) + padder.finalize()
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()
    return encrypted_text


def decrypt_symmetric(text: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(text) + decryptor.finalize()
    unpadder = padding.ANSIX923(64).unpadder()
    unpadded_decrypted_text = unpadder.update(decrypted_text) + unpadder.finalize()
    return unpadded_decrypted_text
