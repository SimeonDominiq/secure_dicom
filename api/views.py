import hashlib
import os
import random
import string
import json
import pydicom

from rest_framework.response import Response
from rest_framework.decorators import api_view
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from django.conf import settings
from django.http import HttpResponseBadRequest

upload_dir = os.path.join(os.getcwd(), 'uploads')
secret_dir = os.path.join(os.getcwd(), 'secrets')


def generate_random_filename():
    # Generate a random string of alphanumeric characters
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    # Hash the random string using SHA-256
    hash_object = hashlib.sha256(random_string.encode())
    file_hash = hash_object.hexdigest()

    return file_hash


# Function to generate a random key and IV
def generate_key_iv():
    key = hashlib.sha256(get_random_bytes(32)).digest()  # Generate a random 256-bit key
    iv = get_random_bytes(16)  # Generate a random IV (Initialization Vector)
    return key, iv


def retrieve_key_iv(key_iv_path):
    # Load key and IV from file
    with open(key_iv_path, 'r') as key_iv_file:
        key_iv_data = json.load(key_iv_file)
    key = bytes.fromhex(key_iv_data['key'])
    iv = bytes.fromhex(key_iv_data['iv'])

    return key, iv


def pad(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def un_pad(padded_data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def read_dicom_data(filepath):
    dicom_dataset = pydicom.dcmread(filepath)
    data_to_encrypt = dicom_dataset.pixel_array.tobytes()
    return data_to_encrypt


def encrypt(data, key, iv):
    # Initialize a PKCS7 padder with a block size of 128 bits. This will add padding to the data so its length is a multiple of the AES block size (16 bytes).
    # Then, pad the input data and finalize the padding process to ensure the data is ready for encryption.
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Create a cipher setup for encryption using AES algorithm in CBC mode. This setup uses the secret key and an initialization vector (IV) for encryption.
    # The 'default_backend()' part tells the program where to get the necessary cryptographic functions from.
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

    encryptor = cipher.encryptor()

    # Encrypt the data that's been padded to make sure it fits perfectly for encryption. This turns
    # the readable padded data into a scrambled format (ciphertext) that can't be read without decrypting.
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


def decrypt_data(encrypted_data, key, iv):
    # Creates a new cipher object for decryption, specifying the use of the AES algorithm in CBC mode, with the provided key and iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()

    # decrypts the ciphertext using the decryptor object
    padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

    # original plaintext was padded to fit the block size required by AES, this line initializes an unpadder object to remove that padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def save_decrypted_data_as_dicom(decrypted_data, decrypted_file_path):
    template_dicom_path = os.path.join(settings.BASE_DIR, 'template', 'base_template.dcm')
    # Load an existing DICOM file to use as a template
    ds = pydicom.dcmread(template_dicom_path)

    # Assuming the decrypted data is raw pixel data that matches the template's specifications
    ds.PixelData = decrypted_data

    # Save the modified DICOM file
    ds.save_as(decrypted_file_path)
    print(f"Decrypted DICOM saved to {decrypted_file_path}")


@api_view(['POST'])
def encrypt_dicom_files(request):
    if request.FILES:
        uploaded_files = request.FILES.getlist('files')
        uploaded_data = []
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        for file in uploaded_files:
            dicom_data = read_dicom_data(file)
            key, iv = generate_key_iv()
            encrypted_data = encrypt(dicom_data, key, iv)
            file_hash = generate_random_filename()
            file_path = os.path.join('uploads', file_hash)

            with open(file_path, 'wb+') as destination:
                destination.write(encrypted_data)

            # Check if the secrets (holds the key & iv) directory exists, if not create one
            if not os.path.exists(secret_dir):
                os.makedirs(secret_dir)

            # Save key and IV to a separate folder
            key_iv_dict = {'key': key.hex(), 'iv': iv.hex()}
            with open(os.path.join('secrets', file_hash + '.json'), 'w') as key_iv_file:
                json.dump(key_iv_dict, key_iv_file)
            uploaded_data.append(file_hash)
        return Response({'uploaded_files': uploaded_data})
    return HttpResponseBadRequest({'error': 'No files were uploaded'}, status=400)


@api_view(['GET'])
def decrypt_dicom_files(request, file_hash):
    # Check if the file hash exists
    key_iv_path = os.path.join(settings.BASE_DIR, 'secrets', file_hash + '.json')
    if not os.path.exists(key_iv_path):
        return HttpResponseBadRequest('File not found')

    key, iv = retrieve_key_iv(key_iv_path)
    # Construct file paths
    encrypted_file_path = os.path.join(settings.BASE_DIR, 'uploads', file_hash)
    decrypted_file_path = os.path.join(settings.BASE_DIR, 'decrypted', file_hash + '.dcm')

    # Decrypt the file and save decrypted content
    try:
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        decrypted_data = decrypt_data(encrypted_data, key, iv)
        save_decrypted_data_as_dicom(decrypted_data, decrypted_file_path)
        return Response({'decrypted_file': decrypted_file_path})
    except Exception as e:
        return HttpResponseBadRequest('Error decrypting file: ' + str(e))
