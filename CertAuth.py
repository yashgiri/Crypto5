# from cryptography import x509, exceptions
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.backends import default_backend
import cryptography
from OpenSSL.crypto import *


def task1():
    crt_data = open("subject.crt", "rb").read()
    subject_certificate = load_certificate(FILETYPE_PEM, crt_data)

    root_crt_data = open("root.crt", "rb").read()
    root_certificate = load_certificate(FILETYPE_PEM, root_crt_data)
    # task1

    root_cert_store = X509Store()
    root_cert_store.add_cert(root_certificate)
    root_store_context = X509StoreContext(root_cert_store, subject_certificate)

    try:
        root_store_context.verify_certificate()
    except X509StoreContextError:
        print(False)
    else:
        print(True)

    # task2
    print(subject_certificate.get_subject().CN)
    print(subject_certificate.get_issuer().CN)
    print(subject_certificate.get_serial_number())
    print(subject_certificate.get_signature_algorithm().decode())
    print(subject_certificate.get_notBefore().decode())
    print(subject_certificate.get_notAfter().decode())

    # task 3
    print()


if  __name__ == "__main__":
    task1()