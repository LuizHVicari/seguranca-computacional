from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


class Signature():
    def __init__(self, message, key):
        assert message is None or type(message)  == str
        self.message = message.encode() if type(message) == str else message
        self.key = key



class UncipherSignatureSender(Signature):
    def __init__(self, private_key, message : str = 'test message'):
        assert type(message) == str
        super().__init__(message, private_key)
        self.signer = DSS.new(self.key, 'fips-186-3')


    def send(self):
        hash_obj = SHA256.new(self.message)
        signature = self.signer.sign(hash_obj)
        output = self.message + signature
        return output


class UncipherSignatureReceiver(Signature):
    def __init__(self, public_key, input):
        super().__init__(None, public_key)
        self.input = input


    def receive(self):
        message, signature = self.input[:-56], self.input[-56:]
        hash_obj = SHA256.new(message)
        verifier = DSS.new(self.key, 'fips-186-3')

        try:
            verifier.verify(hash_obj, signature)
            output = True
        except:
            output = False

        return output


class CipherSignatureSender(UncipherSignatureSender):
    def __init__(self,
            private_key,
            symetric_key : bytes = b'Sixteen byte key',
            iv : bytes = b'Sixteen byte key',
            message : str = 'test message'):
        assert type(message) == str
        super().__init__(private_key, message)
        self.symetric_key = symetric_key
        self.cipher = AES.new(symetric_key, AES.MODE_CFB, iv=iv)


    def esend(self):
        output = self.send()
        encrypted_output = self.cipher.encrypt(output)
        return encrypted_output


class CipherSignatureReceiver(UncipherSignatureReceiver):
    def __init__(self, input, public_key, symetric_key = b'Sixteen byte key', iv = b'Sixteen byte key'):
        super().__init__(public_key, input)
        decipher = AES.new(symetric_key, AES.MODE_CFB, iv=iv)
        self.input = decipher.decrypt(input)
