import customtkinter
from tkinter import *
import os
import base32hex
import hashlib
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

key = get_random_bytes(8)

WIDTH = 300
TEXTO = 'teste'

root = customtkinter.CTk()
root.title('Criptografia')
root.geometry("400x600")

scrollable_frame = customtkinter.CTkScrollableFrame(root, width=300, height=800, scrollbar_button_color="#1f6aa5", scrollbar_button_hover_color="#144870", fg_color="#242424")

customtkinter.set_appearance_mode("Dark")


def build_output(token_encrypted, token_decrypted):
        output = f'''
        Texto criptografado:\n {token_encrypted},
        Texto descriptografado:\n {token_decrypted}
        '''
        label = customtkinter.CTkLabel(scrollable_frame, text=output, wraplength=200)
        label.pack(pady=10, padx=5)


def proccess_crypto_text(text : str):
    e_cipher = DES.new(key, DES.MODE_EAX)
    token_encrypted = e_cipher.encrypt(text.encode())

    d_cipher = DES.new(key, DES.MODE_EAX, e_cipher.nonce)
    token_decrypted = d_cipher.decrypt(token_encrypted).decode()

    build_output(token_encrypted, token_decrypted)


def input_cr():
    text = textbox.get()
    proccess_crypto_text(text)


def crypto_file():
    path = textbox.get()
    with open(path, 'r') as f:
        text = f.read()

    proccess_crypto_text(text)


def crypto_bin_file():
    path = textbox.get()
    with open(path, 'rb') as file:
        file_content = file.read()

    e_cipher = DES.new(key, DES.MODE_EAX)
    token_encrypted = e_cipher.encrypt(file_content)

    d_cipher = DES.new(key, DES.MODE_EAX, e_cipher.nonce)
    token_decrypted = d_cipher.decrypt(token_encrypted)

    file_name, file_extension = path.split('/')[-1].split('.')

    with open(f'{file_name}_encrypted.{file_extension}', 'wb') as file:
        file.write(token_encrypted)

    with open(f'{file_name}_decrypted.{file_extension}', 'wb') as file:
        file.write(token_decrypted)

    directory = os.getcwd()
    output = f'''
    A imagem criptografada e descriptografada podem ser encontradas em {directory}
    '''

    label = customtkinter.CTkLabel(scrollable_frame, text=output, wraplength=200)
    label.pack(pady=10, padx=5)



textbox = customtkinter.CTkEntry(root, placeholder_text='Texto a ser criptografado ou caminho do arquivo', width=WIDTH)
button_code = customtkinter.CTkButton(root, command=lambda : proccess_crypto_text(TEXTO), width=WIDTH, text='Criptografar texto no código')
button_input = customtkinter.CTkButton(root, command=input_cr, width=WIDTH, text='Criptografar texto inserido')
button_file_text = customtkinter.CTkButton(root, command=crypto_file, width=WIDTH, text='Criptografar arquivo de texto')
button_file_bin = customtkinter.CTkButton(root, command=crypto_bin_file, width=WIDTH, text='Criptografar arquivo binário')
hl = '____________________________________________________________'
hl1 = customtkinter.CTkLabel(root, text=hl, text_color="#2b2b2b")
crypto_labels = customtkinter.CTkLabel(root, text='Mensagens criptografadas:')
hl2 = customtkinter.CTkLabel(root, text=hl, text_color="#2b2b2b")

textbox.pack(pady=10, padx=20)
button_code.pack(pady=10, padx=0)
button_input.pack(pady=10, padx=0)
button_file_text.pack(pady=10, padx=20)
button_file_bin.pack(pady=10, padx=20)
hl1.pack(padx=20)
crypto_labels.pack(padx=20)
hl2.pack(padx=20)
scrollable_frame.pack(side=BOTTOM, fill=X)

root.mainloop()
