from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC

def generate_keys(sk_file, pk_file):
    key = RSA.generate(2048)
    with open(sk_file, "wb") as f:
        f.write(key.export_key())
    with open(pk_file, "wb") as f:
        f.write(key.publickey().export_key())
    return key

def encrypt_message(receiver_pk_file, message):
    # Load receiver's public key
    with open(receiver_pk_file, "rb") as f:
        receiver_key = RSA.import_key(f.read())

    # Generate AES key
    aes_key = get_random_bytes(16)  # AES-128
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

    # Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(receiver_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # Generate MAC
    mac = HMAC.new(aes_key, digestmod=SHA256)
    mac.update(ciphertext)

    # Save to file
    with open("Transmitted_Data", "wb") as f:
        f.write(enc_aes_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(mac.digest())
        f.write(ciphertext)

def decrypt_message(private_key_file):
    # Load private key
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())

    # Read transmitted data
    with open("Transmitted_Data", "rb") as f:
        enc_aes_key = f.read(private_key.size_in_bytes())
        nonce = f.read(16)
        tag = f.read(16)
        mac_value = f.read(32)
        ciphertext = f.read()

    # Decrypt AES key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    # Decrypt message
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce)
    message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Verify MAC
    mac = HMAC.new(aes_key, digestmod=SHA256)
    mac.update(ciphertext)
    try:
        mac.verify(mac_value)
        print("MAC verified.")
    except ValueError:
        print("MAC verification failed!")

    print("The message is:", message.decode())

def main():
    sender_pk = "sender_pk.pem"
    sender_sk = "sender_sk.pem"
    receiver_pk = "receiver_pk.pem"
    receiver_sk = "receiver_sk.pem"
    
    # RSA key gen for both
    generate_keys(sender_sk, sender_pk)
    generate_keys(receiver_sk, receiver_pk)
    
    # Encrypt and send
    message = 'Uni is very cute'
    encrypt_message(receiver_pk, message)
    
    # Decrypt and read
    decrypt_message(receiver_sk)

if __name__ == "__main__":
    main()
    
    
    