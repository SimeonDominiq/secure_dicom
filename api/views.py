import hashlib
import os

from rest_framework.response import Response
from rest_framework.decorators import api_view
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from pprint import pprint


def pad(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the data that's been padded to make sure it fits perfectly for encryption. This turns
    # the readable padded data into a scrambled format (ciphertext) that can't be read without decrypting.
    ciphertext = encryptor.update(pad(data)) + encryptor.finalize()
    return ciphertext


@api_view(['GET'])
def get_data(request):
    person = {'name': 'Opeyemi', 'age': 23}
    return Response(person)


@api_view(['POST'])
def encrypt_files(request):
    if request.FILES:
        uploaded_files = request.FILES.getlist('files')
        file_names = []
        upload_dir = os.path.join(os.getcwd(), 'uploads')
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
        for file in uploaded_files:
            key = hashlib.sha256(get_random_bytes(32)).digest()  # Generate a random 256-bit key
            iv = get_random_bytes(16)  # Generate a random IV (Initialization Vector)
            file_name = file.name
            file_path = os.path.join('uploads', file_name)
            with open(file_path, 'wb+') as destination:
                for chunk in file.chunks():
                    encrypted_chunk = encrypt(chunk, key, iv)
                    destination.write(encrypted_chunk)
            file_names.append(file_name)
        return Response({'file_names': file_names})
    return Response({'error': 'No files were uploaded'}, status=400)
