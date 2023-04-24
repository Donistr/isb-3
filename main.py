from asymmetric import generate_asymmetric_keys, encrypt_asymmetric, decrypt_asymmetric
from symmetric import generate_symmetric_keys, encrypt_symmetric, decrypt_symmetric
from files_functions import read_settings, save_asymmetric_private_key, read_asymmetric_private_key, read_text, \
    write_text
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    program_mode_group = parser.add_mutually_exclusive_group(required=True)
    program_mode_group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
    program_mode_group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
    program_mode_group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
    args = parser.parse_args()
    if read_settings():
        if args.generation:
            symmetric_key, nonce = generate_symmetric_keys()
            private_key, public_key = generate_asymmetric_keys()
            save_asymmetric_private_key(private_key)
            encrypted_symmetric_key = encrypt_asymmetric(symmetric_key, public_key)
            encrypted_nonce = encrypt_asymmetric(nonce, public_key)
            write_text(encrypted_symmetric_key, 'symmetric_key')
            write_text(encrypted_nonce, 'nonce')
        elif args.encryption:
            private_key = read_asymmetric_private_key()
            encrypted_symmetric_key = read_text('symmetric_key')
            encrypted_nonce = read_text('nonce')
            symmetric_key = decrypt_asymmetric(encrypted_symmetric_key, private_key)
            nonce = decrypt_asymmetric(encrypted_nonce, private_key)
            text = read_text('initial_file')
            encrypted_text = encrypt_symmetric(text, symmetric_key, nonce)
            write_text(encrypted_text, 'encrypted_file')
        elif args.decryption:
            private_key = read_asymmetric_private_key()
            encrypted_symmetric_key = read_text('symmetric_key')
            encrypted_nonce = read_text('nonce')
            symmetric_key = decrypt_asymmetric(encrypted_symmetric_key, private_key)
            nonce = decrypt_asymmetric(encrypted_nonce, private_key)
            encrypted_text = read_text('encrypted_file')
            decrypted_text = decrypt_symmetric(encrypted_text, symmetric_key, nonce)
            write_text(decrypted_text, 'decrypted_file')
