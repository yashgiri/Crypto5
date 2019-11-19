from cryptography import x509
from cryptography.hazmat.backends import default_backend


def task1():
    crt_data = open("subject.crt", "rb").read()

    # task1
    cert = x509.load_pem_x509_certificate(crt_data , default_backend())

    # task2
    print(cert.subject)
    print(cert.issuer)
    print(cert.serial_number)
    print(cert.signature_hash_algorithm)
    print(cert.not_valid_before)
    print(cert.not_valid_after)

    # task 3
    print("\n")
    print(cert.public_key())


if  __name__ == "__main__":
    task1()