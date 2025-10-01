from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def AES_Encryption(data: bytes, key: bytes) -> bytes:
    # AES key must be 16, 24, or 32 bytes
    cipher = AES.new(key[:16], AES.MODE_CBC)  # using first 16 bytes of key
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    # prepend IV for decryption
    return base64.b64encode(cipher.iv + ct_bytes)

def AES_Decryption(enc_data: bytes, key: bytes) -> bytes:
    raw = base64.b64decode(enc_data)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key[:16], AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def AES_Encryption_File(filename: str, key: bytes) -> str:
    with open(filename, 'rb') as f:
        data = f.read()
    enc_data = AES_Encryption(data, key)
    enc_filename = filename + ".enc"
    with open(enc_filename, 'wb') as f:
        f.write(enc_data)
    return enc_filename

def AES_Decryption_File(enc_filename: str, key: bytes) -> bytes:
    with open(enc_filename, 'rb') as f:
        enc_data = f.read()
    dec_data = AES_Decryption(enc_data, key)
    return dec_data

# Main program
if __name__ == "__main__":

    key = b'1234sfsfdsafasdf'
    plaintext = b'Hello World'
    plaintext_b64 = base64.b64encode(plaintext)
    print("Base64 plaintext:", plaintext_b64)

    enc_message = AES_Encryption(plaintext_b64, key)
    print("Encrypted message:", enc_message)

    original_message = AES_Decryption(enc_message, key)
    print("Decrypted equals original:", plaintext_b64 == original_message)

    # Create a test file
    with open('hello.txt', 'wb') as f:
        f.write(plaintext)

    enc_file = AES_Encryption_File('hello.txt', key)
    print("Encrypted file:", enc_file)

    dec_file = AES_Decryption_File(enc_file, key)
    dec_file = base64.b64encode(dec_file)  # encode file content in base64
    print("Decrypted file content (base64):", dec_file)
