from Crypto.PublicKey import RSA

def generate_and_save_keys(name):
    key = RSA.generate(2048)
    with open(f"{name}_public.pem", "w") as f:
        f.write(key.publickey().export_key().decode())
    with open(f"{name}_private.pem", "w") as f:
        f.write(key.export_key().decode())

generate_and_save_keys("alice")
generate_and_save_keys("bob")
print("Keys generated for Alice and Bob.")
