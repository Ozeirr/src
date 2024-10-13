import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_keys():
    """
    Genereer RSA publieke en private sleutels en sla ze op in bestanden.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Sla de private sleutel op
    with open("data/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Sla de publieke sleutel op
    with open("data/public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key() -> rsa.RSAPrivateKey:
    """
    Laad de private sleutel uit het bestand.
    """
    try:
        with open("data/private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key
    except FileNotFoundError:
        raise Exception("Private key file not found. Ensure 'private_key.pem' is generated and placed in 'data' directory.")

def load_public_key() -> rsa.RSAPublicKey:
    """
    Laad de publieke sleutel uit het bestand.
    """
    try:
        with open("data/public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        return public_key
    except FileNotFoundError:
        raise Exception("Public key file not found. Ensure 'public_key.pem' is generated and placed in 'data' directory.")

def encrypt_data(data: str) -> str:
    """
    Versleutel de gegeven data met behulp van RSA publieke sleutel encryptie.
    """
    public_key = load_public_key()
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data.hex()

def decrypt_data(encrypted_data: str) -> str:
    """
    Ontsleutel de gegeven versleutelde data met behulp van RSA private sleutel decryptie.
    """
    private_key = load_private_key()
    decrypted_data = private_key.decrypt(
        bytes.fromhex(encrypted_data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode()