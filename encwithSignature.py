import hashlib
import os

def xor_crypt(data, key):
    key = key * (len(data) // len(key) + 1)
    key = key[:len(data)]
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ ord(key[i]))
    return bytes(encrypted_data)

def encrypt_file(input_file_path, output_file_path, key):
    with open(input_file_path, 'rb') as input_file:
        data = input_file.read()

    # Encrypt the file contents
    encrypted_data = xor_crypt(data, key)

    # Write the encrypted data to the output file
    with open(output_file_path, 'wb') as output_file:
        output_file.write(encrypted_data)

    os.remove(input_file_path)
    print(f'Original file "{input_file_path}" deleted.')

def decrypt_file(input_file_path, output_file_path, key):
    with open(input_file_path, 'rb') as input_file:
        encrypted_data = input_file.read()

    # Decrypt the file contents
    decrypted_data = xor_crypt(encrypted_data, key)

    # Write the decrypted data to the output file
    with open(output_file_path, 'wb') as output_file:
        output_file.write(decrypted_data)

    print(f'{input_file_path} decrypted and saved as {output_file_path}')

def create_signature(file_path, password):
    # Read the file contents
    with open(file_path, 'rb') as file:
        data = file.read()

    # Combine the file data and password
    signature_data = data + password.encode()

    # Calculate the SHA-256 hash of the signature data
    signature = hashlib.sha256(signature_data).hexdigest()

    return signature

def verify_signature(file_path, password, signature):
    # Recreate the signature and compare with the provided signature
    calculated_signature = create_signature(file_path, password)
    return calculated_signature == signature

file_path = input("Enter the file path: ")
password = input("Enter the password: ")

# Create the digital signature
signature = create_signature(file_path, password)
print("Digital signature:", signature)

# Verify the digital signature
verified = verify_signature(file_path, password, signature)

if verified:
    print("Digital signature is valid. Access granted.")
    action = input("Enter 'encrypt' or 'decrypt' to choose the action: ")

    if action == 'encrypt':
        output_file_path = file_path + '.crypt'
        key = input("Enter the encryption key: ")
        print(f'Encrypting {file_path}...')
        encrypt_file(file_path, output_file_path, key)
        print(f'{file_path} encrypted and saved as {output_file_path}')
    elif action == 'decrypt':
        output_file_path = os.path.splitext(file_path)[0]
        key = input("Enter the decryption key: ")
        print(f'Decrypting {file_path}...')
        decrypt_file(file_path, output_file_path, key)
    else:
        print('Invalid action. Please choose either "encrypt" or "decrypt".')
else:
    print("Digital signature is invalid. Access denied.")