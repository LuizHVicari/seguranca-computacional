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
    """
    Envia a saída correspondente a figura 1
    Garante confidencialidade pois a mensagem é criptografada
    """
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
    """
    Recebe a saída correspondente a figura 1
    """
    def __init__(self, key, iv, input, message=None):
        assert not message
        super().__init__(key, iv)
        self.input = input


    def destiny(self):
        decipher_input = self.decipher(self.input)
        message, hash_message = decipher_input[:-32], decipher_input[-32:]

        return self.hasher(message) == hash_message, message


class Figura2Origin(Auth):
    """
    Envia a saída correspondente a figura 2
    Garante autenticidade pois a hash é criptografada
    """
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
    """
    Recebe a saída correspondente a figura 2
    """
    def __init__(self, key, iv, input, message=None):
        assert not message
        super().__init__(key, iv)
        self.input = input


    def destiny(self):
        message, encripted_hash = self.input[:-32], self.input[-32:]
        message_hash = self.hasher(message)
        input_hash = self.decipher(encripted_hash)
        return message_hash == input_hash, message


class AsyCipher(Auth):
    """
    Módulo para gerenciar as chaves assimétricas e a criptografia assimétrica
    """
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
    """
    Envia a saída correspondente a figura 3
    Garante assinatura por conta da criptografia assimétrica
    """
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
    """
    Recebe a saída correspondente a figura 3
    """
    def __init__(self, key, iv, private_key, public_key, input, message=None):
        assert not message
        super().__init__(key, iv, private_key, public_key, message)
        self.input = input


    def destiny(self):
        message, hash_message = self.input[:-256], self.input[-256:]
        hash_message_decripted = self.asy_decipher(hash_message)
        input_message_hash = self.hasher(message)

        return hash_message_decripted == input_message_hash, message


class Figura4Origin(Figura3Origin):
    """
    Envia a saída correspondente a figura 4
    Garante confidencialidade pois a mensagem é criptografada
    """
    def __init__(self, key, iv, private_key, public_key, message, **kwargs):
        assert message
        super().__init__(key, iv, private_key, public_key, message)
        self.origin()
        self.output = self.cipher(self.output)


class Figura4Destiny(Figura3Destiny):
    """
    Recebe a saída correspondente a figura 4
    """
    def __init__(self, key, iv, private_key, public_key, input, message=None):
        assert not message
        super().__init__(key, iv, private_key, public_key, message)
        self.input = self.decipher(input)


class Figura5Origin(Auth):
    """
    Envia a saída correspondente a figura 5
    Garante segurança maior graças ao salt e, como todas as outras, tem verificação de integridade
    """
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
    """
    Recebe a saída correspondente a figura 5
    """
    def __init__(self, key, iv, input, message=None, salt=b'2023_e_tem_gente_usando_php_ainda?'):
        assert not message
        super().__init__(key, iv)
        self.input = input
        self.salt = salt


    def destiny(self):
        message, hash_salt_message = self.input[:-32],self.input[-32:]
        message_salt = message + self.salt
        hash_salt_message_destiny = self.hasher(message_salt)

        return hash_salt_message == hash_salt_message_destiny, message


class Figura6Origin(Figura5Origin):
    """
    Envia a saída correspondente a figura 6
    Garante confidencialidade pois a mensagem é criptografada, maior segurança graças ao salt
    """
    def __init__(self, key, iv, message, salt=b'2023_e_tem_gente_usando_php_ainda?'):
        assert message
        super().__init__(key, iv, message)
        self.origin()
        self.output = self.cipher(self.output)


class Figura6Destiny(Figura5Destiny):
    """
    Recebe a saída correspondente a figura 6
    """
    def __init__(self, key, iv, input, message=None, salt=b'2023_e_tem_gente_usando_php_ainda?'):
        assert not message
        super().__init__(key, iv, input, message, salt)
        self.input = self.decipher(input)


if __name__ == '__main__':
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    private_key, public_key = get_asy_keys()


    def print_figure_output(figure_number, figure_origin_class, figure_destiny_class,  last=False, **kwargs,):
        print("="*70)
        print(f'FIGURA {figure_number}')

        if kwargs.keys() >= {'private_key', 'public_key'}:
            fig_origin = figure_origin_class(key, iv, kwargs['private_key'], kwargs['public_key'], b'teste_figura_1')
            fig_destiny = figure_destiny_class(key, iv, kwargs['private_key'], kwargs['public_key'], fig_origin.output)
        else:
            fig_origin = figure_origin_class(key, iv, b'teste_figura_1')
            fig_destiny = figure_destiny_class(key, iv, fig_origin.output)
        fig_destiny_comparison, fig_destiny_message = fig_destiny.destiny()
        print("Saída de Source A:\n", end="\t")
        print(fig_origin.output)
        print("Saída de Source B:")
        print("\tResultado da comparação: ", end="\n\t\t")
        print(fig_destiny_comparison, end="\n")
        print("\tMensagem: ", end="\n\t\t")
        print(fig_destiny_message)


    print_figure_output(1, Figura1Origin, Figura1Destiny, message=b'teste_figura_1')
    print_figure_output(2, Figura2Origin, Figura2Destiny, message=b'teste_figura_2')
    print_figure_output(3, Figura3Origin, Figura3Destiny, private_key=private_key, public_key=public_key, message=b'teste_figura_3')
    print_figure_output(4, Figura4Origin, Figura4Destiny, private_key=private_key, public_key=public_key, message=b'teste_figura_4')
    print_figure_output(5, Figura5Origin, Figura5Destiny, message=b'teste_figura_5')
    print_figure_output(6, Figura6Origin, Figura6Destiny, message=b'teste_figura_6', last=True)
