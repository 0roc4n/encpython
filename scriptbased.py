import os
import time

def xor_crypt(data, key):
    key = key * (len(data) // len(key) + 1)
    key = key[:len(data)]
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i])
    return bytes(encrypted_data)

def encrypt_file(input_file_path, output_file_path, key):
    with open(input_file_path, 'rb') as input_file:
        data = input_file.read()
        with open(output_file_path, 'wb') as output_file:
            for i in range(len(data)):
                output_file.write(xor_crypt(bytes([data[i]]), key))
                time.sleep(0.01)
                print('*', end='', flush=True)
        print('\nEncryption complete.')

    os.remove(input_file_path)
    print(f'Original file "{input_file_path}" deleted.')

def decrypt_file(input_file_path, output_file_path, key):
    with open(input_file_path, 'rb') as input_file:
        data = input_file.read()
        with open(output_file_path, 'wb') as output_file:
            for i in range(len(data)):
                output_file.write(xor_crypt(bytes([data[i]]), key))
                time.sleep(0.01)
                print('*', end='', flush=True)
        print('\nDecryption complete.')

print("Python Encrypt/Decrypt file using XOR Cipher")
print()

action = input("Enter 'encrypt' or 'decrypt' to choose the action: ")
file_path = input("Enter the file path: ")
key = input("Enter the encryption/decryption key: ").encode()

if not os.path.isfile(file_path):
    print(f'Error: File "{file_path}" not found.')
    exit(1)

if action == 'encrypt':
    output_file_path = file_path + '.crypt'
    print(f'Encrypting {file_path}...')
    encrypt_file(file_path, output_file_path, key)
    print(f'{file_path} encrypted and saved as {output_file_path}')
elif action == 'decrypt':
    output_file_path = os.path.splitext(file_path)[0]
    print(f'Decrypting {file_path}...')
    decrypt_file(file_path, output_file_path, key)
    print(f'{file_path} decrypted and saved as {output_file_path}')
else:
    print('Invalid action. Please choose either "encrypt" or "decrypt".')