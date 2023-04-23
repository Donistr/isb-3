import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import logging

logger = logging.getLogger()
logger.setLevel('INFO')


def read_settings(file_name: str = 'settings.json') -> dict:
    """
    функция считывает файл настроек
    :param file_name: название файла с настройками
    :return: настройки
    """
    settings = None
    try:
        with open(file_name) as json_file:
            settings = json.load(json_file)
        logging.info(f'Настройки считаны из файла {file_name}')
    except OSError as err:
        logging.info(f'{err} - ошибка при чтении настроек из файла {file_name}')
    return settings


def save_asymmetric_private_key(private_key, settings_file_name: str = 'settings.json') -> None:
    """
    функция сохраняет приватный ключ для ассиметричного шифрования
    :param private_key: приватный ключ
    :param settings_file_name: название файла с настройками
    :return: ничего
    """
    settings = read_settings(settings_file_name)
    private_key_file_name = settings['secret_key']
    try:
        with open(private_key_file_name, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
        logging.info(f'Приватный ключ сохранён в файл {private_key_file_name}')
    except OSError as err:
        logging.info(f'{err} - ошибка при сохранении приватного ключа {private_key_file_name}')


def read_asymmetric_private_key(settings_file_name: str = 'settings.json'):
    """
    функция считывает сохранённый ранее приватный ключ для ассиметричного шифрования
    :param settings_file_name: название файла с настройками
    :return: приватный ключ
    """
    settings = read_settings(settings_file_name)
    private_key_file_name = settings['secret_key']
    private_key = None
    try:
        with open(private_key_file_name, 'rb') as pem_in:
            private_bytes = pem_in.read()
        private_key = load_pem_private_key(private_bytes, password=None)
        logging.info(f'Приватный ключ считан из файла {private_key_file_name}')
    except OSError as err:
        logging.info(f'{err} - ошибка при чтении приватного ключа из файла {private_key_file_name}')
    return private_key


def save_asymmetric_public_key(public_key, settings_file_name: str = 'settings.json') -> None:
    """
    функция сохраняет публичный ключ для ассиметричного шифрования
    :param public_key: публичный ключ
    :param settings_file_name: название файла с настройками
    :return: ничего
    """
    settings = read_settings(settings_file_name)
    public_key_file_name = settings['public_key']
    try:
        with open(public_key_file_name, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
        logging.info(f'Публичный ключ сохранён в файл {public_key_file_name}')
    except OSError as err:
        logging.info(f'{err} - ошибка при чтении публичного ключа из файла {public_key_file_name}')


def read_asymmetric_public_key(settings_file_name: str = 'settings.json'):
    """
    функция считывает сохранённый ранее публичный ключ для ассиметричного шифрования
    :param settings_file_name: название файла с настройками
    :return: публичный ключ
    """
    settings = read_settings(settings_file_name)
    public_key_file_name = settings['public_key']
    public_key = None
    try:
        with open(public_key_file_name, 'rb') as pem_in:
            private_bytes = pem_in.read()
        public_key = load_pem_public_key(private_bytes)
        logging.info(f'Публичный ключ считан из файла {public_key_file_name}')
    except OSError as err:
        logging.info(f'{err} - ошибка при чтении публичного ключа из файла {public_key_file_name}')
    return public_key


def save_key(key: bytes, file_name: str, settings_file_name: str = 'settings.json') -> None:
    """
    функция сохраняет ключ в файл file_name
    :param key: ключ
    :param file_name: название файла
    :param settings_file_name: название файла с настройками
    :return: ничего
    """
    settings = read_settings(settings_file_name)
    key_file_name = settings[file_name]
    try:
        with open(key_file_name, 'wb') as file:
            file.write(key)
        logging.info(f'Ключ сохранён в файл {key_file_name}')
    except OSError as err:
        logging.info(f'{err} - ошибка при сохранении ключа в файл {key_file_name}')


def read_key(file_name: str, settings_file_name: str = 'settings.json') -> bytes:
    """
    функция считывает ранее сохранённый ключ из файла file_name
    :param file_name: название файла
    :param settings_file_name: название файла с настройками
    :return: ключ
    """
    settings = read_settings(settings_file_name)
    key_file_name = settings[file_name]
    key = None
    try:
        with open(key_file_name, mode='rb') as file:
            key = file.read()
        logging.info(f'Ключ считан из файла {key_file_name}')
    except OSError as err:
        logging.info(f'{err} - ошибка при чтении ключа из файла {key_file_name}')
    return key


def read_text(file_name: str, settings_file_name: str = 'settings.json') -> bytes:
    """
    функция считывает текстовый файл
    :param file_name: название файла
    :param settings_file_name: название файла с настройками
    :return: текст из файла
    """
    settings = read_settings(settings_file_name)
    text_file_name = settings[file_name]
    text = None
    try:
        with open(text_file_name, mode='rb') as text_file:
            text = text_file.read()
        logging.info(f'Файл {text_file_name} прочитан')
    except OSError as err:
        logging.info(f'{err} - ошибка при чтении файла {text_file_name}')
    return text


def write_text(text: bytes, file_name: str, settings_file_name: str = 'settings.json') -> None:
    """
    функция записывает текст в файл
    :param text: текст
    :param file_name: название файла
    :param settings_file_name: название файла с настройками
    :return: ничего
    """
    settings = read_settings(settings_file_name)
    text_file_name = settings[file_name]
    try:
        with open(text_file_name, mode='wb') as text_file:
            text_file.write(text)
        logging.info(f'Текст записан в файл {text_file_name}')
    except OSError as err:
        logging.info(f'{err} - ошибка при записи в файл {text_file_name}')
