import socket
from classes import UncipherSignatureReceiver, CipherSignatureReceiver

class Socket():
    def __init__(self, host : str = 'localhost', port : int = 65432):
        self.host = host
        self.port = port


    def runserver(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)
                    if data:
                        conn.sendall(data)
                        return data
                    conn.sendall(data)
        return data



    def runclient(self, message : str = 'Hello, world'):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            if type(message) == str:
                s.sendall(message.encode('utf-8'))
            else:
                s.sendall(message)
            data = s.recv(1024)

