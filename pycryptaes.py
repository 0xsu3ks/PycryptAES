import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def aes_decrypt(key, enc_data):
    enc_data = b64decode(enc_data)
    nonce = enc_data[:16]
    tag = enc_data[16:32]
    ciphertext = enc_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def main():
    parser = argparse.ArgumentParser(description='Simple AES-256 Encryption/Decryption Script')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--encrypt', help='Input string to encrypt')
    group.add_argument('--decrypt', help='Input string to decrypt')
    parser.add_argument('--key', required=True, help='Input AES key. It must be a 32-byte long string.')
    args = parser.parse_args()

    key = args.key.encode()
    
    
    if len(key) > 32:
        raise ValueError("AES key must not be more than 32 bytes long")
    elif len(key) < 32:
        key = key.ljust(32, b'\0')

    if args.encrypt:
        data = args.encrypt.encode()
        encrypted_data = aes_encrypt(key, data)
        print("Encrypted data:", encrypted_data)
    elif args.decrypt:
        decrypted_data = aes_decrypt(key, args.decrypt)
        print("Decrypted data:", decrypted_data.decode('utf-8'))
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes long")


if __name__ == "__main__":
    main()
