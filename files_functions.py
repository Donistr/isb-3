import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def read_settings(file_name: str = 'settings.json') -> dict:
    try:
        with open(file_name) as json_file:
            settings = json.load(json_file)
    except OSError as err:
        print(err)
    return settings


def save_asymmetric_private_key(private_key: bytes, settings_file_name: str = 'settings.json') -> None:
    settings = read_settings(settings_file_name)
    private_key_file_name = settings['secret_key']
    try:
        with open(private_key_file_name, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
    except OSError as err:
        print(err)


def read_asymmetric_private_key(settings_file_name: str = 'settings.json') -> bytes:
    settings = read_settings(settings_file_name)
    private_key_file_name = settings['secret_key']
    private_key = None
    try:
        with open(private_key_file_name, 'rb') as pem_in:
            private_bytes = pem_in.read()
        private_key = load_pem_private_key(private_bytes, password=None)
    except OSError as err:
        print(err)
    return private_key


def save_asymmetric_public_key(public_key: bytes, settings_file_name: str = 'settings.json') -> None:
    settings = read_settings(settings_file_name)
    public_key_file_name = settings['public_key']
    try:
        with open(public_key_file_name, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
    except OSError as err:
        print(err)


def read_asymmetric_public_key(settings_file_name: str = 'settings.json') -> bytes:
    settings = read_settings(settings_file_name)
    public_key_file_name = settings['secret_key']
    public_key = None
    try:
        with open(public_key_file_name, 'rb') as pem_in:
            private_bytes = pem_in.read()
        public_key = load_pem_public_key(private_bytes)
    except OSError as err:
        print(err)
    return public_key


def save_symmetric_key(symmetric_key: bytes, settings_file_name: str = 'settings.json') -> None:
    settings = read_settings(settings_file_name)
    symmetric_key_file_name = settings['symmetric_key']
    try:
        with open(symmetric_key_file_name, 'wb') as key_file:
            key_file.write(symmetric_key)
    except OSError as err:
        print(err)


def read_symmetric_key(settings_file_name: str = 'settings.json') -> bytes:
    settings = read_settings(settings_file_name)
    symmetric_key_file_name = settings['symmetric_key']
    try:
        with open(symmetric_key_file_name, mode='rb') as key_file:
            key = key_file.read()
    except OSError as err:
        print(err)
    return key


def save_nonce(symmetric_key: bytes, settings_file_name: str = 'settings.json') -> None:
    settings = read_settings(settings_file_name)
    symmetric_key_file_name = settings['nonce']
    try:
        with open(symmetric_key_file_name, 'wb') as key_file:
            key_file.write(symmetric_key)
    except OSError as err:
        print(err)


def read_nonce(settings_file_name: str = 'settings.json') -> bytes:
    settings = read_settings(settings_file_name)
    nonce_file_name = settings['nonce']
    try:
        with open(nonce_file_name, mode='rb') as nonce_file:
            nonce = nonce_file.read()
    except OSError as err:
        print(err)
    return nonce


def read_encrypted_text(settings_file_name: str = 'settings.json') -> bytes:
    settings = read_settings(settings_file_name)
    encrypted_text_file_name = settings['encrypted_file']
    try:
        with open(encrypted_text_file_name, mode='rb') as text_file:
            text = text_file.read()
    except OSError as err:
        print(err)
    return text


def write_decrypted_text(decrypted_text: bytes, settings_file_name: str = 'settings.json') -> None:
    settings = read_settings(settings_file_name)
    decrypted_text_file_name = settings['decrypted_file']
    try:
        with open(decrypted_text_file_name, mode='wb') as text_file:
            text_file.write(decrypted_text)
    except OSError as err:
        print(err)
