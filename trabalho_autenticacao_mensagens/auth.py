from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from keys import get_asy_keys


class Auth():
    def __init__(self, key, iv, message=None):
        assert type(message) == bytes or message == None, 'message must be bytes'
        self.message = message
        self.key = key
        self.iv = iv

    def hasher(self, message = None):
        message = self.message if not message else message
        m = sha256()
        m.update(message)

        self.hash_message = m.digest()
        return self.hash_message


    def cipher(self, message=None):
        message = self.message if not message else message
        cipher = AES.new(self.key, AES.MODE_CFB, self.iv)
        self.cipher_text = cipher.encrypt(message)
        return self.cipher_text


    def decipher(self, cipher_text=None):
        cipher_text = self.cipher_text if not cipher_text else cipher_text
        cipher = AES.new(self.key, AES.MODE_CFB, self.iv)
        self.plain_text = cipher.decrypt(cipher_text)
        return self.plain_text


class Figura1Origin(Auth):
    def __init__(self, key, iv, message):
        assert message
        super().__init__(key, iv, message)
        self.origin()


    def origin(self):
        hash_ = self.hasher()
        hash_and_message = self.message + hash_
        self.output = self.cipher(hash_and_message)
        return self.output


class Figura1Destiny(Auth):
    def __init__(self, key, iv, input, message=None):
        assert not message
        super().__init__(key, iv)
        self.input = input


    def destiny(self):
        decipher_input = self.decipher(self.input)
        message, hash_ = decipher_input[:-32], decipher_input[-32:]

        return self.hasher(message) == hash_


class Figura2Origin(Auth):
    def __init__(self, key, iv, message):
        assert message
        super().__init__(key, iv, message)
        self.origin()


    def origin(self):
        hash_message = self.hasher()
        encrypted_hash_message = self.cipher(hash_message)
        self.output = self.message + encrypted_hash_message
        return self.output


class Figura2Destiny(Auth):
    def __init__(self, key, iv, input, message=None):
        assert not message
        super().__init__(key, iv)
        self.input = input


    def destiny(self):
        message, encripted_hash = self.input[:-32], self.input[-32:]
        message_hash = self.hasher(message)
        input_hash = self.decipher(encripted_hash)
        return message_hash == input_hash


class AsyCipher(Auth):
    def __init__(self, key, iv, private_key, public_key, message):
        assert type(message) == bytes or message == None, 'message must be bytes'
        super().__init__(key, iv, message)

        self.private_key = private_key
        self.public_key = public_key


    def asy_cipher(self, message=None):
        message = self.message if not message else message
        cipher_text = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return cipher_text


    def asy_decipher(self, message):
        message = self.message if not message else message
        plain_text = private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plain_text


class Figura3Origin(AsyCipher):
    def __init__(self, key, iv, private_key, public_key, message):
        assert message
        super().__init__(key, iv, private_key, public_key, message)
        self.origin()


    def origin(self):
        hash_message = self.hasher()
        encrypted_hash_message = self.asy_cipher(hash_message)
        self.output = self.message + encrypted_hash_message

        return self.output


class Figura3Destiny(AsyCipher):
    def __init__(self, key, iv, private_key, public_key, input, message=None):
        assert not message
        super().__init__(key, iv, private_key, public_key, message)
        self.input = input


    def destiny(self):
        message, hash_message = self.input[:-256], self.input[-256:]
        hash_message_decripted = self.asy_decipher(hash_message)
        input_message_hash = self.hasher(message)

        return hash_message_decripted == input_message_hash


class Figura4Origin(Figura3Origin):
    def __init__(self, key, iv, private_key, public_key, message):
        assert message
        super().__init__(key, iv, private_key, public_key, message)
        self.origin()
        self.output = self.cipher(self.output)


class Figura4Destiny(Figura3Destiny):
    def __init__(self, key, iv, private_key, public_key, input, message=None):
        assert not message
        super().__init__(key, iv, private_key, public_key, message)
        self.input = self.decipher(input)


class Figura5Origin(Auth):
    def __init__(self, key, iv, message, salt=b'2023_e_tem_gente_usando_php_ainda?'):
        assert message
        super().__init__(key, iv, message)
        assert type(salt) == bytes, 'salt must be bytes'
        self.salt = salt
        self.origin()


    def origin(self):
        message = self.message + self.salt
        hash_salt_message = self.hasher(message)
        self.output = self.message + hash_salt_message
        return self.output


class Figura5Destiny(Auth):
    def __init__(self, key, iv, input, message=None, salt=b'2023_e_tem_gente_usando_php_ainda?'):
        assert not message
        super().__init__(key, iv)
        self.input = input
        self.salt = salt


    def destiny(self):
        message, hash_salt_message = self.input[:-32],self.input[-32:]
        message_salt = message + self.salt
        hash_salt_message_destiny = self.hasher(message_salt)

        return hash_salt_message == hash_salt_message_destiny


class Figura6Origin(Figura5Origin):
    def __init__(self, key, iv, message, salt=b'2023_e_tem_gente_usando_php_ainda?'):
        assert message
        super().__init__(key, iv, message)
        self.origin()
        self.output = self.cipher(self.output)


class Figura6Destiny(Figura5Destiny):
    def __init__(self, key, iv, input, message=None, salt=b'2023_e_tem_gente_usando_php_ainda?'):
        assert not message
        super().__init__(key, iv, input, message, salt)
        self.input = self.decipher(input)




if __name__ == '__main__':
    key = get_random_bytes(16)
    iv = get_random_bytes(16)

    private_key, public_key = get_asy_keys()

    print("FIGURA 1:")

    fig1_origin = Figura1Origin(key, iv, b'teste_figura_1')
    print(fig1_origin.output)

    fig1_destiny = Figura1Destiny(key, iv, fig1_origin.output)
    result = fig1_destiny.destiny()
    print(result)

    print("FIGURA 2:")

    fig2_origin = Figura2Origin(key, iv, b'teste_figura_3')
    print(fig2_origin.output)

    fig2_destiny = Figura2Destiny(key, iv, fig2_origin.output)
    print(fig2_destiny.destiny())

    print("FIGURA 3:")
    fig3_origin = Figura3Origin(key, iv,private_key, public_key, b'teste_figura_3')
    print(fig3_origin.output)

    fig3_destiny = Figura3Destiny(key, iv, private_key, public_key, fig3_origin.output)
    print(fig3_destiny.destiny())

    print("FIGURA 4:")
    fig4_origin = Figura4Origin(key, iv, private_key, public_key, b'teste_figura_4')
    print(fig4_origin.output)

    fig4_destiny = Figura4Destiny(key, iv, private_key, public_key, fig4_origin.output)
    print(fig4_destiny.destiny())

    print("FIGURA 5:")
    fig5_origin = Figura5Origin(key, iv, b'teste_figura_5')
    print(fig5_origin.output)

    fig5_destiny = Figura5Destiny(key, iv, fig5_origin.output)
    print(fig5_destiny.destiny())

    print("FIGURA 6:")
    fig6_origin = Figura6Origin(key, iv, b'teste_figura_6')
    print(fig6_origin.output)

    fig6_destiny = Figura6Destiny(key, iv, fig6_origin.output)
    print(fig6_destiny.destiny())
