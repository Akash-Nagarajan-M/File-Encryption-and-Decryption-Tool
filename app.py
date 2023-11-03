import gradio as gr
import sqlite3
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os
from cryptography.hazmat.backends import default_backend  # Import the default_backend

def load_private_key(private_key_pem):
    # Decode the PEM data
    private_key_data = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    return x25519.X25519PrivateKey.from_private_bytes(private_key_data.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()))

def load_public_key(public_key_pem):
    # Decode the PEM data
    public_key_data = serialization.load_pem_public_key(public_key_pem, backend=default_backend)
    return public_key_data
# Function to perform Diffie-Hellman key exchange and derive a shared key
def perform_diffie_hellman(sender_private_key, receiver_public_key):
    shared_key = sender_private_key.exchange(receiver_public_key)
    return shared_key

# Function to handle both encryption and decryption
def process_file(input_file, sender_name, receiver_name, mode):
    # Fetch sender's private key and receiver's public key from the database
    connection = sqlite3.connect("user_keys.db")
    cursor = connection.cursor()
    cursor.execute("SELECT private_key FROM user_keys WHERE user_name = ?", (sender_name,))
    sender_private_key_data = cursor.fetchone()
    cursor.execute("SELECT public_key FROM user_keys WHERE user_name = ?", (receiver_name,))
    receiver_public_key_data = cursor.fetchone()
    connection.close()
    print(sender_private_key_data)
    print(receiver_public_key_data)
    if not sender_private_key_data or not receiver_public_key_data:
        return "Sender or receiver not found in the database."

     # Deserialize sender's private key and receiver's public key
    sender_private_key_pem = sender_private_key_data[0]
    sender_private_key = load_private_key(sender_private_key_pem)
    receiver_public_key_pem = receiver_public_key_data[0]
    receiver_public_key = load_public_key(receiver_public_key_pem)


    # Perform Diffie-Hellman key exchange
    shared_key = perform_diffie_hellman(sender_private_key, receiver_public_key)
    
    key = shared_key[:16]  # Use the first 16 bytes of the shared key as the AES key
    input_file_path = input_file.name

    if mode == "Encrypt":
        output_file = "encrypted/" + os.path.basename(input_file_path)
        with open(input_file_path, 'rb') as file:
            plaintext = file.read()

        # Calculate the SHA-256 hash of the plaintext
        plaintext_hash = SHA256.new(plaintext).digest()

        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        print("Hash in encr:", plaintext_hash)
        # Combine the nonce, ciphertext, and plaintext hash
        encrypted_data = nonce + ciphertext + plaintext_hash

        with open(output_file, 'wb') as file:
            file.write(encrypted_data)

        return output_file
    elif mode == "Decrypt":
        output_file = "decrypted/" + os.path.basename(input_file_path)
        with open(input_file_path, 'rb') as file:
            encrypted_data = file.read()

        # Extract the nonce, ciphertext, and plaintext hash
        nonce = encrypted_data[:16]
        ciphertext = encrypted_data[16:-32]
        plaintext_hash = encrypted_data[-32:]
        print("Hash in decr:", plaintext_hash)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)

        # Verify the integrity of the decrypted plaintext
        calculated_hash = SHA256.new(plaintext).digest()
        print("Calc hash:", calculated_hash)
        if calculated_hash != plaintext_hash:
            return "Data integrity check failed. The file may have been tampered with."

        with open(output_file, 'wb') as file:
            file.write(plaintext)

        return output_file

iface = gr.Interface(
    fn=process_file,
    inputs=[
        gr.inputs.File(label="File"),
        "text",
        "text",
        gr.inputs.Radio(["Encrypt", "Decrypt"], label="Mode")
    ],
    outputs="file",
    layout="vertical",
    title="File Encryption and Decryption (AES + SHA + Diffie Hellman)",
    description="Encrypt and decrypt a text file using AES encryption.\nVerify its data integrity with SHA-256 hashing.\n Diffie-Hellman key exchange is performed to establish a shared secret key.",
)

iface.launch(share=True)
