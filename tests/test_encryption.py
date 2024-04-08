import unittest
from unittest.mock import patch
from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIRequestFactory
from api.views import encrypt_dicom_files


class EncryptDicomFilesTestCase(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    @patch('api.views.generate_key_iv')
    @patch('api.views.generate_random_filename')
    @patch('api.views.encrypt_file')
    def test_encrypt_dicom_files(self, mock_encrypt_file, mock_generate_random_filename, mock_generate_key_iv):
        # Mock generate_key_iv to return fixed key and IV
        mock_generate_key_iv.return_value = b'fixed_key', b'fixed_iv'

        # Mock generate_random_filename to return a fixed file hash
        mock_generate_random_filename.return_value = 'fixed_file_hash'

        # Create mock files for the request
        files = [
            SimpleUploadedFile('file1.dcm', b'content1'),
            SimpleUploadedFile('file2.dcm', b'content2'),
        ]

        # Create request with mock files
        request = self.factory.post('/encrypt_dicom_files/', {'files': files}, format='multipart')

        # Call the view function
        response = encrypt_dicom_files(request)

        # Assert that the view returns a Response with status code 200
        self.assertEqual(response.status_code, 200)

        # Assert that generate_key_iv was called twice (once for each file)
        self.assertEqual(mock_generate_key_iv.call_count, 2)

        # Assert that generate_random_filename was called twice (once for each file)
        self.assertEqual(mock_generate_random_filename.call_count, 2)

        # Assert that the response contains the correct uploaded file hashes
        self.assertEqual(response.data['uploaded_files'], ['fixed_file_hash', 'fixed_file_hash'])

    @patch('api.views.generate_key_iv')
    @patch('api.views.generate_random_filename')
    @patch('api.views.encrypt_file')
    def test_encrypt_dicom_files_no_files(self, mock_encrypt_file, mock_generate_random_filename, mock_generate_key_iv):
        # Create request with no files
        request = self.factory.post('/encrypt_dicom_files/', format='multipart')

        # Call the view function
        response = encrypt_dicom_files(request)

        # Assert that the view returns a Response with status code 400 (Bad Request)
        self.assertEqual(response.status_code, 400)

        # Assert that generate_key_iv and generate_random_filename were not called
        mock_generate_key_iv.assert_not_called()
        mock_generate_random_filename.assert_not_called()

        # Assert that encrypt_file was not called
        mock_encrypt_file.assert_not_called()

        # Assert that the response contains the correct error message
        self.assertEqual(response.data['error'], 'No files were uploaded')


if __name__ == '__main__':
    unittest.main()
