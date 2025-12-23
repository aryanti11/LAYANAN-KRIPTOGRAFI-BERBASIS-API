# File dari sisi client 
# Lengkapi file ini dengan proses-proses pembuatan private, public key, pembuatan pesan rahasia
# TIPS: Untuk private, public key bisa dibuat di sini lalu disimpan dalam file
# sebelum mengakses laman Swagger API

import os
import json
import base64
from urllib import request, parse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER = "http://localhost:8080"

PRIV = "punkhazard-keys/privkey_097.pem"
PUB  = "punkhazard-keys/pubkey_097.pem"


# =====================================
# Generate EC keypair
# =====================================
def generate_keys():
    if os.path.exists(PRIV) and os.path.exists(PUB):
        print("[OK] Keys exist")
        return

    priv = ec.generate_private_key(ec.SECP256R1())
    priv_bytes = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    open(PRIV, "wb").write(priv_bytes)

    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    open(PUB, "wb").write(pub_bytes)

    print("[OK] New EC keys generated")


# =====================================
# Sign message
# =====================================
def sign_message(message):
    priv = serialization.load_pem_private_key(open(PRIV, "rb").read(), None)
    signature = priv.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode()


# =====================================
# AES encryption
# =====================================
def encrypt_message(msg: str):
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, msg.encode(), None)

    return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode(), key

# =====================================
# Relay message (JSON)
# =====================================
def relay(sender, receiver, ciphertext, nonce):
    payload = {
        "sender": sender,
        "receiver": receiver,
        "ciphertext": ciphertext,
        "nonce": nonce
    }

    data = json.dumps(payload).encode("utf-8")

    req = request.Request(
        f"{SERVER}/relay",
        data=data,
        method="POST"
    )
    req.add_header("Content-Type", "application/json")

    resp = request.urlopen(req)
    print("[RELAY]", resp.read().decode())

# =====================================
# MAIN
# =====================================
if __name__ == "__main__":

    # 1. Generate keypair (jika belum ada)
    generate_keys()

    # 2. Buat signature untuk diuji di /verify
    message = "Halo Aryanti, Aisyah, Sabrina"
    signature_b64 = sign_message(message)

    print("Public key   :", PUB)
    print("Private key  :", PRIV)
    print("Message      :", message)
    print("Signature    :", signature_b64)

    # 3. Enkripsi pesan untuk dikirim di /relay
    ciphertext, nonce, aeskey = encrypt_message(
        "ini pesan rahasia dari Intan"
    )

    print("Ciphertext   :", ciphertext)
    print("Nonce        :", nonce)

    print("\n=== NEXT STEPS (MANUAL VIA SWAGGER) ===")
    print("1. Buka http://localhost:8080/docs")
    print("2. Upload public key ke endpoint /store (isi username bebas)")
    print("3. Uji signature di endpoint /verify (isi username, message, signature)")
    print("4. Kirim encrypted message di /relay (isi sender, receiver, ciphertext, nonce)")