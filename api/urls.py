from django.urls import path
from . import views


urlpatterns = [
    path('encrypt-files/', views.encrypt_dicom_files),
    path('decrypt-files/<str:file_hash>/', views.decrypt_dicom_files)
]