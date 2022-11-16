from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.rsa import _rsa_sig_recover, _RSAPublicKey
from typing import Tuple, cast


def get_public_rsa_key(file: str = "rsapubkey.pem") -> RSAPublicKey:
    with open("rsapubkey.pem", "rb") as pub_key_file:
        return serialization.load_pem_public_key(pub_key_file.read())


def get_signature_and_message(
    signed_file: str, message: str = "text_clar.txt"
) -> Tuple[bytes, bytes]:
    with open(signed_file, "rb") as signature:
        with open(message, "rb") as message:
            return signature.read(), message.read()


def check_signature_1():
    public_key = get_public_rsa_key()
    signature, message = get_signature_and_message(signed_file="text_signat.bin")
    if isinstance(public_key, _RSAPublicKey):
        cast(public_key, _RSAPublicKey)
        backend = public_key._backend
        my_bytes = _rsa_sig_recover(
            backend=backend,
            padding=PKCS1v15(),
            algorithm=None,
            public_key=public_key,
            signature=signature,
        )
        if message == my_bytes:
            print("Signature 1 (rsautl) is valid")
        else:
            print("Signature 1 (rsautl) is not valid")


def check_signature_2():
    public_key = get_public_rsa_key()
    signature, message = get_signature_and_message(signed_file="text_signat2.bin")
    try:
        public_key.verify(signature, message, PKCS1v15(), SHA1())
        print("Signature 2 (digst -sha1 -sign) is valid")
    except InvalidSignature:
        print("Signature 2 (digst -sha1 -sign) isn't valid.")


if __name__ == "__main__":
    check_signature_1()
    check_signature_2()
