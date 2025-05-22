# AK rsa key generation 

from Cryptodome.PublicKey import RSA
# main program starts here
header="A Simple Program to generate RSA key pair."

secret_phrase = input("Type in a pass phrase please =>")

#Keypair Generation
print("Generating an RSA key pair...")
rsakey_pair=RSA.generate(2048)
print("Done generating the key pair.")

#Storing Keypair
print("export the keypair to 'privatekey.der' with AES encryption in binary format")
prikey_in_der=rsakey_pair.export_key(format="DER", passphrase=secret_phrase, pkcs=8,protection="scryptAndAES128-CBC")
try:
    open("privatekey2.der","wb").write(prikey_in_der)
    print("Export private key has been completed")
except:
    print("Opps! failed to export the private key")
    sys.exit(-1)
pubkey_in_pem=rsakey_pair.publickey().exportKey()
print("export the public key to 'publickey.der' with Base64 format")
try:
    open("publickey2.pem","wb").write(pubkey_in_pem)
    print("Export public key has been completed")
except:
    print("Opps! failed to export the public key")
    sys.exit(-1)
