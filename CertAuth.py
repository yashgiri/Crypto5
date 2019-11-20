#!/usr/bin/env python3
from cryptography import x509, exceptions
# from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
#import cryptography
import argparse
from OpenSSL.crypto import *


def parse():
    parser = argparse.ArgumentParser(description="Applied Cryptography assignment 5",
                                     usage="python3 CertAuth.py Certs/cert_bckup.p12 Certs/root.crt Certs/subject.crt "
                                           "CSE539_Rocks!")
    parser.add_argument('arguments', type=str, nargs=4)
    args = parser.parse_args()
    return args.arguments


def task1(arguments):

    PRIVATE_KEY_FILE_PATH = arguments[0]
    ROOT_CERT_FILE_PATH = arguments[1]
    SUBJECT_CERT_FILE_PATH = arguments[2]
    PRIVATE_KEY_PASSWORD = arguments[3]


    # load the certificate files
    # using 'with open(...) as file' closes the file automatically
    with open(SUBJECT_CERT_FILE_PATH, "rb") as file: 
        crt_data = file.read()
        subject_certificate = load_certificate(FILETYPE_PEM, crt_data)
        subject_certificate_x509 = x509.load_pem_x509_certificate(crt_data, default_backend())
    
    with open(ROOT_CERT_FILE_PATH, "rb") as file:
        root_crt_data = file.read()
        root_certificate = load_certificate(FILETYPE_PEM, root_crt_data)
        root_certificate_x509 = x509.load_pem_x509_certificate(root_crt_data, default_backend())
    
    with open(PRIVATE_KEY_FILE_PATH, "rb") as file:
        subject_pkcs12 = load_pkcs12(file.read(), PRIVATE_KEY_PASSWORD)
        
    # task 1

    root_cert_store = X509Store()
    root_cert_store.add_cert(root_certificate)
    root_store_context = X509StoreContext(root_cert_store, subject_certificate)

    try:
        root_store_context.verify_certificate()
    except X509StoreContextError:
        print(False)
    else:
        print(True)

    # task 2
    print(subject_certificate.get_subject().CN)
    print(subject_certificate.get_issuer().CN)
    print(subject_certificate.get_serial_number())
    print(subject_certificate.get_signature_algorithm().decode())
    print(subject_certificate.get_notBefore().decode())
    print(subject_certificate.get_notAfter().decode())

    # task 3
    subject_numbers = subject_certificate_x509.public_key().public_numbers()
    subject_private_numbers = subject_pkcs12.get_privatekey().to_cryptography_key().private_numbers()
    print(subject_numbers.n)
    print(subject_numbers.e)
    print(subject_private_numbers.d)
    
    # task 4
    root_numbers = root_certificate_x509.public_key().public_numbers()
    print(root_numbers.n)
    print(root_numbers.e)

    # task 5 - Signature
    subject_x509_data = open(SUBJECT_CERT_FILE_PATH, "rb").read()
    subject_x509 = x509.load_pem_x509_certificate(subject_x509_data, default_backend())
    signature = subject_x509.signature
    sign = []
    for char in signature:
        sign.append('{0:02x}'.format(int(char)))
    print("".join(sign))

    # task 6
    # subject_cert_x509_data = open(SUBJECT_CERT_FILE_PATH, "rb").read()
    # subject_cert_x509 = x509.load_pem_x509_certificate(subject_cert_x509_data, default_backend())
    # pubkey = subject_cert_x509.
    # publickey.encrypt(b"Hello World", )

if  __name__ == "__main__":

    args = parse()
    task1(args)