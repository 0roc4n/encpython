import argparse
import os
import time

def xor_crypt(data, key):
    # Repeat the key so that its le ngth matches that of the data
    key = key * (len(data) // len(key) + 1)
    key = key[:len(data)]
    # XOR the data with the key
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i])
    return bytes(encrypted_data)

# Define the encryption and decryption functions
def encrypt_file(input_file_path, output_file_path, key):
    with open(input_file_path, 'rb') as input_file:
        data = input_file.read()
        with open(output_file_path, 'wb') as output_file:
            for i in range(len(data)):
                output_file.write(xor_crypt(bytes([data[i]]), key))
                time.sleep(0.01)
                print('*', end='', flush=True)
        print('\nEncryption complete.')

def decrypt_file(input_file_path, output_file_path, key):
    with open(input_file_path, 'rb') as input_file:
        data = input_file.read()
        with open(output_file_path, 'wb') as output_file:
            for i in range(len(data)):
                output_file.write(xor_crypt(bytes([data[i]]), key))
                time.sleep(0.01)
                print('*', end='', flush=True)
        print('\nDecryption complete.')
def menu():
    print("Python Encrypt/Decrypt file using XOR Cipher")
    print("")

# Define the command line interface
parser = argparse.ArgumentParser(description='Encrypt or decrypt a file.')
subparsers = parser.add_subparsers(dest='command')

encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
encrypt_parser.add_argument('input_file', type=str, help='The file to encrypt')
encrypt_parser.add_argument('-k', '--key', type=str, required=True, help='The encryption key')

decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
decrypt_parser.add_argument('input_file', type=str, help='The file to decrypt')
decrypt_parser.add_argument('-k', '--key', type=str, required=True, help='The decryption key')

args = parser.parse_args()

# Check the command and perform the corresponding action
if args.command == 'encrypt':
    input_file_path = args.input_file
    output_file_path = input_file_path + '.crypt'
    key = args.key.encode()
    print(f'Encrypting {input_file_path}...')
    encrypt_file(input_file_path, output_file_path, key)
    print(f'{input_file_path} encrypted and saved as {output_file_path}')

elif args.command == 'decrypt':
    input_file_path = args.input_file
    output_file_path = os.path.splitext(input_file_path)[0]
    key = args.key.encode()
    print(f'Decrypting {input_file_path}...')
    decrypt_file(input_file_path, output_file_path, key)
    print(f'{input_file_path} decrypted and saved as {output_file_path}')
