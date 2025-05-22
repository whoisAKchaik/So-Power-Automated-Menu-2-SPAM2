from Cryptodome.Signature import pkcs1_15
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
import hashlib
import datetime
import sys
import socket
import os  # Import os for executing PGP commands

global host, port

# Lihao Data integrity check
def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

host = socket.gethostname()
port = 8888  # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
menu_file = "menu_today.txt"
encrypted_menu_file = "menu_today.gpg"  # Encrypted menu file
return_file = "day_end.csv"
encrypted_return_file = "day_end.csv.gpg"  # Encrypted return file

# Step 1: Request the menu from the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_GET_MENU)

    # Receive the filename as a separate message
    filename_header = b""
    while b'\n' not in filename_header:
        filename_header += my_socket.recv(1)
    filename = filename_header.decode("utf8").strip()

    # Receive the file content and verify integrity
    with open(filename, "wb") as dest_file:
        while True:
            # First, receive the hash of the next chunk
            data_hash = my_socket.recv(64).decode('utf-8')  

            # Then, receive the actual data chunk
            data = my_socket.recv(4096)
            if not data:
                break

            # Verify the integrity of the received data chunk
            if compute_hash(data) == data_hash:
                dest_file.write(data)
                print('Menu today received from server and integrity verified.')
            else:
                print('Data integrity check failed!')
                break

    # Decrypt the received menu file
    os.system(f'gpg --yes --output {menu_file} --decrypt {filename}')

    my_socket.close()




# Step 3: Send the end of day sales data to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)

    # AK
    secret_phrase = input("Type in a pass phrase please => ")
    # AK Import private Key to sign 
    print("now try to import back the key pair (the private key)")
    prikey_bytes = open("privatekey.der", "rb").read()
    restored_keypair = RSA.import_key(prikey_bytes, passphrase=secret_phrase)

    # AK Opening the end-day sale
    with open(return_file, "rb") as f:
        file_bytes = f.read()
        
    # AK Signing    
    print("Signing the sha256 digest of the phrase with the private key of the RSA key pair")
    digest = SHA256.new(file_bytes)
    print("digest:")
    for b in digest.digest():
        print("{0:02x}".format(b), end="")
    print("\n")
    signer = pkcs1_15.new(restored_keypair)
    signature = signer.sign(digest)
    print("Signature:")
    for b in signature:
        print("{0:02x}".format(b), end="")
    print("\n")
    # AK Send the signature 
    my_socket.send(signature)    
    
    try:
        # Encrypt the file before sending
        os.system(f'gpg --yes --output {encrypted_return_file} --encrypt --recipient spam2server {return_file}')
        
        # Open and send the encrypted file with filename header
        with open(encrypted_return_file, "rb") as enc_out_file:
            # Send filename
            my_socket.sendall(f"{encrypted_return_file}\n".encode())  
            # Send file data
            file_bytes = enc_out_file.read(1024)
            while file_bytes:
                my_socket.send(file_bytes)
                file_bytes = enc_out_file.read(1024)

    except FileNotFoundError:
        print("File not found: " + return_file)
        sys.exit(0)

    my_socket.close()

print('Sale of the day sent to server')
