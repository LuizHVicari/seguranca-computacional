from Crypto.PublicKey import RSA, ECC

def init_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()

    with open('code_keys/private_rsa.pem', 'wb') as f:
        f.write(private_key)

    public_key = key.publickey().export_key()
    with open('code_keys/public_rsa.pem', 'wb') as f:
        f.write(public_key)

init_rsa_keys()


