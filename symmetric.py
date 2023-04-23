from os import urandom
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


def generate_symmetric_keys() -> tuple:
    """
    функция генерирует ключ и nonce для симметричного шифрования
    :return: ключ и nonce
    """
    key = urandom(32)
    nonce = urandom(16)
    return key, nonce


def encrypt_symmetric(text: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    функция шифрует текст алгоритмом симметричного шифрования ChaCha20, с помощью ключа и nonce
    :param text: текст, который шифруем
    :param key: ключ
    :param nonce: nonce
    :return: зашифрованный текст
    """
    padder = padding.ANSIX923(64).padder()
    padded_text = padder.update(text) + padder.finalize()
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(padded_text) + encryptor.finalize()
    return encrypted_text


def decrypt_symmetric(text: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    функция расшифровывает симметрично зашифрованный текст, с помощью ключа и nonce
    :param text: зашифрованный текст
    :param key: ключ
    :param nonce: nonce
    :return: возвращает расшифрованный текст
    """
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(text) + decryptor.finalize()
    unpadder = padding.ANSIX923(64).unpadder()
    unpadded_decrypted_text = unpadder.update(decrypted_text) + unpadder.finalize()
    return unpadded_decrypted_text
