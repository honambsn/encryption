from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1, SHA256



# 1. Phát sinh một khoá bí mật Ks của thuật toán AES
def generate_aes_key():
    key = AES.get_random_bytes(16)  # AES key length is 16 bytes (128 bits)
    return key

# 2. Mã hoá tập tin sử dụng thuật toán AES với khoá Ks
def encrypt_file_aes(filename, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(filename, 'rb') as file:
        plaintext = file.read()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        encrypted_file = filename + '.enc'
        with open(encrypted_file, 'wb') as encrypted:
            encrypted.write(cipher.nonce + tag + ciphertext)

# 3. Giải mã tập tin sử dụng thuật toán AES với khoá Ks
def decrypt_file_aes(filename, key):
    with open(filename, 'rb') as file:
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        decrypted_file = filename[:-4]  # Remove the '.enc' extension
        with open(decrypted_file, 'wb') as decrypted:
            decrypted.write(plaintext)

# 4. Phát sinh một cặp khoá Kprivate và Kpublic của thuật toán RSA
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# 5. Mã hoá một chuỗi sử dụng thuật toán RSA sử dụng khoá Kpublic
def encrypt_string_rsa(string, public_key):
    key = RSA.import_key(public_key)
    ciphertext = key.encrypt(string.encode(), 0)[0]
    return ciphertext

# 6. Giải mã một chuỗi sử dụng thuật toán RSA sử dụng khoá Kprivate
def decrypt_string_rsa(ciphertext, private_key):
    key = RSA.import_key(private_key)
    plaintext = key.decrypt(ciphertext)
    return plaintext.decode()

# 7. Tính giá trị hash của một chuỗi sử dụng thuật toán SHA-1, SHA-256
def calculate_hash(string, algorithm='sha256'):
    hash_object = None
    if algorithm == 'sha1':
        hash_object = SHA1.new()
    elif algorithm == 'sha256':
        hash_object = SHA256.new()
    hash_object.update(string.encode())
    return hash_object.hexdigest()


def generate_rsa_key_pair():
    key_pair = RSA.generate(2048)
    return key_pair

def encrypt_string_with_rsa(string, rsa_public_key):
    cipher = PKCS1_OAEP.new(rsa_public_key)
    encrypted_data = cipher.encrypt(string.encode())
    return encrypted_data

# Decrypt string using RSA private key
def decrypt_string_with_rsa(encrypted_data, rsa_private_key):
    cipher = PKCS1_OAEP.new(rsa_private_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode()


# Sử dụng các chức năng trong module
if __name__ == '__main__':
    # Phát sinh khoá bí mật AES
    aes_key = generate_aes_key()
    print("AES Key:", aes_key.hex())

    # Mã hoá tập tin sử dụng AES
    encrypt_file_aes('D:/Ba Nam/Own project/Practice/encryption/plaintext.txt', aes_key)
    
    # Giải mã tập tin sử dụng AES
    decrypt_file_aes('D:/Ba Nam/Own project/Practice/encryption/plaintext.txt.enc', aes_key)

    # Phát sinh cặp khoá RSA
    private_key, public_key = generate_rsa_keypair()
    print("Private Key:", private_key.decode())
    print("Public Key:", public_key.decode())

    # Mã hoá chuỗi sử dụng khoá public RSA
    
    rsa_key_pair = generate_rsa_key_pair()

    encrypted_string = encrypt_string_with_rsa('Hello, World!', rsa_key_pair.publickey())

#    encrypted_string = encrypt_string_rsa('Hello, World!', public_key)
    print("Encrypted String:", encrypted_string.hex())

    # Giải mã chuỗi sử dụng khoá private RSA
    decrypted_string = decrypt_string_with_rsa(encrypted_string, rsa_key_pair)

    #decrypted_string = decrypt_string_rsa(encrypted_string, private_key)
    print("Decrypted String:", decrypted_string)

    # Tính giá trị hash của chuỗi
    string = "Hello, World!"
    sha1_hash = calculate_hash(string, algorithm='sha1')
    sha256_hash = calculate_hash(string, algorithm='sha256')
    print("SHA-1 Hash:", sha1_hash)
    print("SHA-256 Hash:", sha256_hash)
