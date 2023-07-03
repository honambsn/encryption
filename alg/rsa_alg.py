from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os




def generate_rsa_key_pair(private_key_path, public_key_path):
    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Save the private key to file
    with open(private_key_path, "wb") as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)
    
    # Extract the public key from the private key
    public_key = private_key.public_key()
    
    # Save the public key to file
    with open(public_key_path, "wb") as public_key_file:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_pem)
    
    return private_key_pem, public_key_pem
    
def key_genned():
    current_directory = os.getcwd()
    private_key_path= current_directory+"\\encryption\\rsa\\private_key.pem"
    public_key_path = current_directory+"\\encryption\\rsa\\public_key.pem"
    generate_rsa_key_pair(private_key_path, public_key_path)
    private_key, public_key = generate_rsa_key_pair(private_key_path,public_key_path)
    return private_key,public_key

def encrypt_file_rsa(file_path, public_key_path, output_path):
    # Load the public key from file
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    
    # Read the file content
    with open(file_path, "rb") as file:
        file_content = file.read()
    
    # Encrypt the file content using RSA encryption
    encrypted_content = public_key.encrypt(
        file_content,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Write the encrypted content to the output file
    with open(output_path, "wb") as output_file:
        output_file.write(encrypted_content)
        


def decrypt_file(encrypted_file, private_key_file, decrypted_file):
    # Load the private key from file
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Read the encrypted file
    with open(encrypted_file, "rb") as file:
        encrypted_data = file.read()

    # Decrypt the encrypted data using RSA private key
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the decrypted data to a new file
    with open(decrypted_file, "wb") as file:
        file.write(decrypted_data)



# # Get the current working directory
# current_directory = os.getcwd()


# # Generate a new RSA key pair
# private_key_path= current_directory+"\\encryption\\rsa\\private_key.pem"
# public_key_path = current_directory+"\\encryption\\rsa\\public_key.pem"
# generate_rsa_key_pair(private_key_path, public_key_path)

# # Encrypt the text file using the public key
# file_path = current_directory+"\\encryption\\plaintext.txt"
# output_path = current_directory+"\\encryption\\rsa\\encrypted_file.txt"
# encrypt_file_rsa(file_path, public_key_path, output_path)


# encrypted_file = current_directory+"\\encryption\\rsa\\encrypted_file.txt"
# private_key_path = current_directory+"\\encryption\\rsa\\private_key.pem"
# decrypted_file = current_directory+"\\encryption\\rsa\\decrypted.txt"
# decrypt_file(encrypted_file, private_key_path, decrypted_file)


# private_key, public_key = generate_rsa_key_pair(private_key_path,public_key_path)
# print(public_key,private_key)