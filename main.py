from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = FastAPI()

# In-memory key store (Replace with a database in production)
keys = {}

class KeyGenRequest(BaseModel):
    key_type: str
    key_size: int

class EncryptRequest(BaseModel):
    key_id: str
    plaintext: str
    algorithm: str

class DecryptRequest(BaseModel):
    key_id: str
    ciphertext: str
    algorithm: str

class HashRequest(BaseModel):
    data: str
    algorithm: str

class HashVerifyRequest(BaseModel):
    data: str
    hash_value: str
    algorithm: str

@app.post("/generate-key")
def generate_key(request: KeyGenRequest):
    if request.key_type == "AES":
        key = os.urandom(request.key_size // 8)
    elif request.key_type == "RSA":
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=request.key_size
        )
        key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported key type")

    key_id = str(len(keys) + 1)
    keys[key_id] = key
    return {"key_id": key_id, "key_value": base64.b64encode(key).decode()}

@app.post("/encrypt")
def encrypt(request: EncryptRequest):
    if request.key_id not in keys:
        raise HTTPException(status_code=404, detail="Key not found")

    key = keys[request.key_id]
    plaintext_bytes = request.plaintext.encode()

    if request.algorithm == "AES":
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = iv + encryptor.update(plaintext_bytes) + encryptor.finalize()
    elif request.algorithm == "RSA":
        public_key = serialization.load_pem_private_key(key, password=None).public_key()
        ciphertext = public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported encryption algorithm")

    return {"ciphertext": base64.b64encode(ciphertext).decode()}

@app.post("/decrypt")
def decrypt(request: DecryptRequest):
    if request.key_id not in keys:
        raise HTTPException(status_code=404, detail="Key not found")

    key = keys[request.key_id]
    ciphertext_bytes = base64.b64decode(request.ciphertext)

    if request.algorithm == "AES":
        iv = ciphertext_bytes[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext_bytes[16:]) + decryptor.finalize()
    elif request.algorithm == "RSA":
        private_key = serialization.load_pem_private_key(key, password=None)
        plaintext = private_key.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported decryption algorithm")

    return {"plaintext": plaintext.decode()}

@app.post("/generate-hash")
def generate_hash(request: HashRequest):
    if request.algorithm == "SHA-256":
        hash_value = hashlib.sha256(request.data.encode()).digest()
    elif request.algorithm == "SHA-512":
        hash_value = hashlib.sha512(request.data.encode()).digest()
    else:
        raise HTTPException(status_code=400, detail="Unsupported hashing algorithm")

    return {"hash_value": base64.b64encode(hash_value).decode(), "algorithm": request.algorithm}

@app.post("/verify-hash")
def verify_hash(request: HashVerifyRequest):
    generated_hash = generate_hash(HashRequest(data=request.data, algorithm=request.algorithm))["hash_value"]
    is_valid = generated_hash == request.hash_value
    return {"is_valid": is_valid, "message": "Hash matches the data." if is_valid else "Hash does not match."}
