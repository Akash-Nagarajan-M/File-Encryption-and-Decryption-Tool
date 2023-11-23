import gradio as gr
import sqlite3
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import binascii


# Function to create the "user_keys" table if it doesn't exist
def create_user_keys_table():
    connection = sqlite3.connect("user_keys.db")
    cursor = connection.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS user_keys (user_name TEXT, private_key BLOB, public_key BLOB)"
    )
    connection.commit()
    connection.close()


# Function to generate a unique Diffie-Hellman key pair for a user
def generate_diffie_hellman_key_pair(user_name):
    create_user_keys_table()  # Create the table if it doesn't exist

    while True:
        # Generate a Diffie-Hellman key pair
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize keys to bytes
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Check if the user already exists in the database
        connection = sqlite3.connect("user_keys.db")
        cursor = connection.cursor()
        cursor.execute(
            "SELECT user_name FROM user_keys WHERE user_name = ?", (user_name,)
        )
        existing_user = cursor.fetchone()

        if existing_user:
            connection.close()
            return "User already exists in the database."

        # Check if the generated private key is unique in the database
        cursor.execute("SELECT private_key FROM user_keys")
        existing_keys = cursor.fetchall()

        private_key_hex = binascii.hexlify(private_key_bytes).decode("utf-8")

        if private_key_hex not in [
            binascii.hexlify(key[0]).decode("utf-8") for key in existing_keys
        ]:
            # Store the user name and key pair in the database
            cursor.execute(
                "INSERT INTO user_keys VALUES (?, ?, ?)",
                (user_name, private_key_bytes, public_key_bytes),
            )
            connection.commit()
            connection.close()
            return "Key pair generated and stored in the database."


# iface = gr.Interface(
#     fn=generate_diffie_hellman_key_pair,
#     inputs="text",
#     outputs="text",
#     layout="vertical",
#     title="Diffie-Hellman Key Pair Generation",
#     description="Generate and store a unique Diffie-Hellman key pair for a user in an SQLite database.",
# )

# iface.launch(share=True)
