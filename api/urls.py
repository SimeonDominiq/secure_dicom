from django.urls import path
from .views import encrypt_dicom_files, decrypt_dicom_files


urlpatterns = [
    path('encrypt-files/', encrypt_dicom_files),
    path('decrypt-files/<str:file_hash>/', decrypt_dicom_files)
]