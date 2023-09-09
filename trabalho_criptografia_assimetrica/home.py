from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key, generate_key

eth_key = generate_eth_key()
private_ecc = eth_key.to_hex()
public_ecc = eth_key.public_key.to_hex()

code_rsa_private = RSA.import_key(open('code_keys/private_rsa.pem').read())
code_rsa_public = RSA.import_key(open('code_keys/public_rsa.pem').read())

open_ssl_private = RSA.import_key(open('open_ssl_keys/private_rsa.pem').read())
open_ssl_public = RSA.import_key(open('open_ssl_keys/public_rsa.pem').read())

ssh_keygen_private = RSA.import_key(open('ssh_keygen_keys/ssh_keygen_rsa').read())
ssh_keygen_public = RSA.import_key(open('ssh_keygen_keys/ssh_keygen_rsa.pub').read())

message = b'Teste de mensagem'

def cipher_rsa(key):
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(message)
    return ciphertext


def decipher_rsa(key, ciphertext):
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def rsa_cipher(key_origin):
    match key_origin:
        case 'code':
            ciphertext = cipher_rsa(code_rsa_public)
            plaintext = decipher_rsa(code_rsa_private, ciphertext)
        case 'open_ssl':
            ciphertext = cipher_rsa(open_ssl_public)
            plaintext = decipher_rsa(open_ssl_private, ciphertext)
        case 'ssh_keygen':
            ciphertext = cipher_rsa(ssh_keygen_public)
            plaintext = decipher_rsa(ssh_keygen_private, ciphertext)
    return ciphertext, plaintext

def ecc():
    ciphertext = encrypt(public_ecc, message)
    plaintext = decrypt(private_ecc, ciphertext)
    return ciphertext, plaintext


origins = ['code', 'open_ssl', 'ssh_keygen']

for origin in origins:
    print(origin.upper() + ':')
    print(rsa_cipher(origin))
    print('='*50 + '\n'*3)

print('ECC:')
print(ecc())


