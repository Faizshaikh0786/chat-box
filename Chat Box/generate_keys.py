from Crypto.PublicKey import RSA

# It generates a new 2048 bit RSA key pair and writes both the public and private keys to .pem files for the given user name. 
def generate_and_save_keys(name):
    key = RSA.generate(2048)
    with open(f"{name}_public.pem", "w") as f:
        f.write(key.publickey().export_key().decode())
    with open(f"{name}_private.pem", "w") as f:
        f.write(key.export_key().decode())
# It generate keys for both alice and bob  
generate_and_save_keys("alice")
generate_and_save_keys("bob")

print("Keys generated for Alice and Bob.")
