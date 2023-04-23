from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_asymmetric_keys() -> tuple:
    """
    функция генерирует ключи для ассиметричного шифрования
    :return: приватный ключ и публичный ключ
    """
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    return private_key, public_key


def encrypt_asymmetric(text: bytes, public_key) -> bytes:
    """
    функция производит ассимутричное шифрование по публичному ключу
    :param text: текст, который шифруем
    :param public_key: публичный ключ
    :return: зашифрованный текст
    """
    encrypted_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                           algorithm=hashes.SHA256(), label=None))
    return encrypted_text


def decrypt_asymmetric(text: bytes, private_key) -> bytes:
    """
    функция расшифровывает ассиметрично зашифрованный текст, с помощью приватного ключа
    :param text: зашифрованный текст
    :param private_key: приватный ключ
    :return: расшифрованный текст
    """
    decrypted_text = private_key.decrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(), label=None))
    return decrypted_text
