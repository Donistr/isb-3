from asymmetric import generate_asymmetric_keys, encrypt_asymmetric, decrypt_asymmetric
from symmetric import generate_symmetric_keys, encrypt_symmetric, decrypt_symmetric
from files_functions import read_settings, FileManager
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-set', '--settings', type=str,
                        help='Использовать собственный файл с настройками (Указать путь к файлу)')
    program_mode_group = parser.add_mutually_exclusive_group(required=True)
    program_mode_group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
    program_mode_group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
    program_mode_group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
    args = parser.parse_args()
    if args.settings:
        file_manager = FileManager(args.settings)
    else:
        file_manager = FileManager()
    if read_settings():
        if args.generation:
            symmetric_key, nonce = generate_symmetric_keys()
            private_key, public_key = generate_asymmetric_keys()
            file_manager.save_asymmetric_private_key(private_key)
            encrypted_symmetric_key = encrypt_asymmetric(symmetric_key, public_key)
            encrypted_nonce = encrypt_asymmetric(nonce, public_key)
            file_manager.write_text(encrypted_symmetric_key, file_manager.get_symmetric_key_path)
            file_manager.write_text(encrypted_nonce, file_manager.get_nonce_path)
        elif args.encryption:
            private_key = file_manager.read_asymmetric_private_key()
            encrypted_symmetric_key = file_manager.read_text(file_manager.get_symmetric_key_path)
            encrypted_nonce = file_manager.read_text(file_manager.get_nonce_path)
            symmetric_key = decrypt_asymmetric(encrypted_symmetric_key, private_key)
            nonce = decrypt_asymmetric(encrypted_nonce, private_key)
            text = file_manager.read_text(file_manager.get_initial_file_path)
            encrypted_text = encrypt_symmetric(text, symmetric_key, nonce)
            file_manager.write_text(encrypted_text, file_manager.get_encrypted_file_path)
        elif args.decryption:
            private_key = file_manager.read_asymmetric_private_key()
            encrypted_symmetric_key = file_manager.read_text(file_manager.get_symmetric_key_path)
            encrypted_nonce = file_manager.read_text(file_manager.get_nonce_path)
            symmetric_key = decrypt_asymmetric(encrypted_symmetric_key, private_key)
            nonce = decrypt_asymmetric(encrypted_nonce, private_key)
            encrypted_text = file_manager.read_text(file_manager.get_encrypted_file_path)
            decrypted_text = decrypt_symmetric(encrypted_text, symmetric_key, nonce)
            file_manager.write_text(decrypted_text, file_manager.get_decrypted_file_path)
