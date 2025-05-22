from Cryptodome.Signature import pkcs1_15 
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from threading import Thread
import hashlib
import socket
import datetime
import sys
import traceback
import time
import os
import ssl

global host, port

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
default_menu = "menu_today.txt"
encrypted_menu = "menu_today.gpg"
default_save_base = "result-"

host = socket.gethostname()     # get the hostname or IP address
port = 8888                     # The port used by the server

# Lihao data integrity check.
def compute_hash(data):
    return hashlib.sha256(data).hexdigest()

def process_connection(conn, ip_addr, MAX_BUFFER_SIZE):
    # Receive the command from the client
    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    
    # Check for the command type
    usr_cmd = net_bytes[0:15].decode("utf8").strip()
    
    if cmd_GET_MENU in usr_cmd:
        # Handle GET_MENU command
        try:
            # Ericia Encrypt the menu file before sending
            os.system(f'gpg --yes --output {encrypted_menu} --encrypt --recipient spam2client {default_menu}')
            
            with open(encrypted_menu, "rb") as src_file:
                # AK Send filename
                conn.sendall(f"{encrypted_menu}\n".encode())
                
                # Ericia read menu file
                while True:
                    read_bytes = src_file.read(MAX_BUFFER_SIZE)
                    if read_bytes == b'':
                        break

                    # Lihao Send hash value of menu_file for data integrity.
                    conn.send(compute_hash(read_bytes).encode('utf-8'))  # Send the hash to the client

                    # Ericia Send the encrypted menu to the client
                    conn.send(read_bytes)
            print("Processed SENDING menu")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()
        return
    
    elif cmd_END_DAY in usr_cmd:
        # AK Receive the signature
        signature = conn.recv(256)
        
        # Handle CLOSING command
        now = datetime.datetime.now()
        filename = default_save_base + ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")
        temp_file = "temp"
        
        # Ericia Open temp file to receive the filename header
        with open(temp_file, "wb") as temp:
            while blk_count == 0:
                net_bytes = conn.recv(MAX_BUFFER_SIZE)
                if net_bytes == b'':
                    break
                # Write to temp file to process header
                temp.write(net_bytes)
                # Extract filename from header
                filename_header = net_bytes.decode("utf8").strip()
                if filename_header:
                    filename = filename_header
                    blk_count += 1
                    break


        # Ericia Open file to write
        with open(filename + ".gpg", "wb") as dest_file:
            while True:
                net_bytes = conn.recv(MAX_BUFFER_SIZE)
                if not net_bytes:
                    break
                dest_file.write(net_bytes)
                
        # AK Define filename to be saved        
        dec_filename = default_save_base + ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")
        # Ericia Decrypt the received file
        try:
            os.system(f'gpg --yes --output {dec_filename} --decrypt {filename}.gpg')

            #os.remove(filename + ".gpg")  # Optional: Remove the encrypted file after decryption
            print("Saving file as " + dec_filename)
        except Exception as e:
            print(f"Error during decryption: {e}")

        # AK Opening the end-day sale
        with open(dec_filename, "rb") as f:
            file_content = f.read()
        #print(file_content)
        digest = SHA256.new(file_content)
        #print(digest)

        # AK Import public Key to verify 
        pubkey_bytes=open("publickey.pem","r").read()
        restored_pubkey=RSA.import_key(pubkey_bytes)
            
        # AK verify the signature
        print("Verifying the Signature of the phrase with the public key of the RSA key pair")
        verifier = pkcs1_15.new(restored_pubkey)
        #release the line below to trigger a invalid signature case.
        #digest=SHA256.new("wrongmess".encode())
        try:
            verifier.verify(digest,signature)
            print("The signature is valid")
        except:
            print("The signature is not valid")
            
        time.sleep(3)  # Simulate processing time
        print("Processed CLOSING done")
    conn.close()

def client_thread(conn, ip, port, MAX_BUFFER_SIZE=4096):
    process_connection(conn, ip, MAX_BUFFER_SIZE)
    print('Connection ' + ip + ':' + port + " ended")

def start_server():
    global host, port

    # Cedrick SSL cert for secure web protocol
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")
    
    # Create socket instance and bind it to the host and port
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('Socket created')
    
    try:
        soc.bind((host, port))
        print('Socket bind complete')
    except socket.error as msg:
        print('Bind failed. Error: ' + str(sys.exc_info()))
        print(msg.with_traceback())
        sys.exit()

    # Start listening on socket and can accept 10 connections
    soc.listen(10)
    print('Socket now listening')

    try:
        while True:
            conn, addr = soc.accept()
            ip, port = str(addr[0]), str(addr[1])
            print('Accepting connection from ' + ip + ':' + port)
            try:
                Thread(target=client_thread, args=(conn, ip, port)).start()
            except:
                print("Error starting client thread!")
                traceback.print_exc()
    except:
        print("Server error!")
        traceback.print_exc()
    finally:
        soc.close()

if __name__ == "__main__":
    start_server()
