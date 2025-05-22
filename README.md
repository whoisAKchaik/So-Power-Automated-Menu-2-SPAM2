# So-Power-Automated-Menu-2-SPAM2
Applied Cryptography

1. Run 2 separate terminal
2. CD to the server directory (using terminal 1)
   2.1  Server directory should contain server.py, menu_today.txt, generate_cert.py, server.key, 	 server.crt, spam2server_private_key.asc, spam2server_pub_key.asc and publickey.pem files
3. Type "python server.py"
   3.1  You should see:-
	a.   Socket Created
        b.   Socket bind complete
        c.   Socket now listening
   	Your server program is successfully setup and is 
        listening for connection now
4. CD to the client directory (using terminal 2)
   4.1  Client directory should contain client.py, day_end.csv, rsa_keyGen.py,
        spam2client_private_key.asc, spam2client_pub_key.asc, privatekey.der and publickey.pem 		files
5. Type "python client.py"
   5.1  You should see:-
	a. Menu today received from server and integrity verified.
	b. A window prompt to enter a passphrase to unlock the OpenPGP secret key. Type 12345678 		   in the password field.
	c. "Menu today received from server and integrity verified.
	    gpg: encrypted with 4096-bit RSA key, ID 86C8F6D5ACA0FE31, created 2024-08-11
      	    "spam2client <spam2client@spam2.com>"" in the terminal
	d. A prompt to enter a pass phrase to unlock rsa private key to sign signature. Type 123 
	   in the terminal.
	e. A hash digest and a signature in hex values
   	f. Sale of the day sent to server
   5.2  Connection terminated and back to command prompt
6. Go back to the server terminal
   6.1  You should see:-
	a. "gpg: encrypted with 4096-bit RSA key, ID 64509C63DDD8C3F1, created 2024-08-11
            "spam2server <spam2server@spam2.com>"" in the terminal.
	b. Saving file as result-<ip>-<date>
	c. "Verifying the Signature of the phrase with the public key of the RSA key pair
	    The signature is valid" if the file or public key of the sender(the client) is
	   authentic.





