from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from classes import (UncipherSignatureSender, UncipherSignatureReceiver, CipherSignatureSender,
CipherSignatureReceiver)
from sockets import Socket
import sys


symetric_key = b'Sixteen byte key'
iv = b'Sixteen byte key'

s = Socket()

if sys.argv[1] == 'server':
    public_key = DSA.import_key(open('public_key.pem').read())
    data = s.runserver()
    
    receiver_cipher = CipherSignatureReceiver(data, public_key, symetric_key, iv)
    receiver_uncipher = UncipherSignatureReceiver(public_key, data)

    if receiver_cipher.receive() or receiver_uncipher.receive():
        print('Mensagem válida')
    else:
        print('Mensagem inválida')

elif sys.argv[1] == 'client':
    private_key = DSA.import_key(open('private_key.pem').read())
    message = input('Informe a mensagem que deseja assinar:')
    is_crypto = True if input('Deseja criptografar a mensagem? (s/n)\n').lower() == 's' else False

    if is_crypto:
        sender = CipherSignatureSender(private_key, symetric_key, iv, message)
        sender_output = sender.esend()
    else:
        sender = UncipherSignatureSender(private_key, message)
        sender_output = sender.send()
    print(sender_output)

    s.runclient(sender_output)

