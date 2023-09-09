import customtkinter
from tkinter import *
import os
import base32hex
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


rv_128 = get_random_bytes(16)
rv_256 = get_random_bytes(32)
iv_16 = get_random_bytes(16)
iv_8 = get_random_bytes(8)

c
TEXT = 'teste'

padding_modes = ('ECB', 'CBC')

root = customtkinter.CTk()
root.title('Criptografia')
root.geometry("400x800")

key_size = customtkinter.StringVar(value='128')
chipher_method = customtkinter.StringVar(value='ECB')
scrollable_frame = customtkinter.CTkScrollableFrame(root, width=300, height=800, scrollbar_button_color="#1f6aa5", scrollbar_button_hover_color="#144870", fg_color="#242424")
customtkinter.set_appearance_mode("dark")

labels = list()


def create_chipers():
    key = rv_128 if key_size.get() == '128' else rv_256

    match chipher_method.get():
        case 'ECB':
            e_cipher = AES.new(key, mode=AES.MODE_ECB)
            d_cipher = AES.new(key, mode=AES.MODE_ECB)
        case 'CBC':
            e_cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv_16)
            d_cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv_16)
        case 'CFB':
            e_cipher = AES.new(key, mode=AES.MODE_CFB, iv=iv_16)
            d_cipher = AES.new(key, mode=AES.MODE_CFB, iv=iv_16)
        case 'OFB':
            e_cipher = AES.new(key, mode=AES.MODE_OFB, iv=iv_16)
            d_cipher = AES.new(key, mode=AES.MODE_OFB, iv=iv_16)
        case 'CTR':
            e_cipher = AES.new(key, mode=AES.MODE_CTR, initial_value=iv_8)
            d_cipher = AES.new(key, mode=AES.MODE_CTR, nonce=e_cipher.nonce, initial_value=iv_8)
        case 'XTS':
            print('não foi encontrado uma implementação do XTS compatível.')

    return e_cipher, d_cipher


def crypto(kind):
    e_cipher, d_cipher = create_chipers()

    match kind:
        case 'code_text':
            text = TEXT.encode()
        case 'input_text':
            text = textbox.get().encode()
        case 'input_file':
            path = textbox.get()
            with open(path, 'r') as f:
                text = f.read().encode()
        case 'input_bin':
            path = textbox.get()
            with open(path, 'rb') as f:
                text = f.read()

    if chipher_method.get() in padding_modes:
        text = pad(text, AES.block_size)

    c_text = e_cipher.encrypt(text)

    if chipher_method.get() in padding_modes:
        p_text = d_cipher.decrypt(c_text)
        p_text = unpad(p_text, AES.block_size)
    else:
        p_text = d_cipher.decrypt(c_text)

    if kind == 'input_bin':
        file_name, file_ext = path.split('.')
        with open(file_name + '_encrypted.' + file_ext, 'wb') as file:
            file.write(c_text)
        with open(file_name + '_decrypted.' + file_ext, 'wb') as file:
            file.write(p_text)
        output = 'Imagem Criptografada Criada\n'

    else:
        output = f'''
        Texto criptografado:\n {c_text},
        Texto descriptografado:\n {p_text.decode()}
        '''
    label = customtkinter.CTkLabel(scrollable_frame, text=output, wraplength=200)
    label.pack(pady=10, padx=5)
    labels.append(label)


def clear_labels():
    for label in labels:
        label.destroy()
    labels.clear()


def clear_files():
    if 'arquivos_teste' in os.listdir():
        for file in os.listdir('arquivos_teste'):
            if '_decrypted' in file or '_encrypted' in file:
                os.remove('arquivos_teste/' + file)


textbox = customtkinter.CTkEntry(root, placeholder_text='Texto a ser criptografado ou caminho do arquivo', width=WIDTH)
button_code = customtkinter.CTkButton(root, command=lambda : crypto('code_text'), width=WIDTH, text='Criptografar texto no código')
button_input = customtkinter.CTkButton(root, command=lambda: crypto('input_text'), width=WIDTH, text='Criptografar texto inserido')
button_file_text = customtkinter.CTkButton(root, command=lambda: crypto('input_file'), width=WIDTH, text='Criptografar arquivo de texto')
button_file_bin = customtkinter.CTkButton(root, command=lambda: crypto('input_bin'), width=WIDTH, text='Criptografar arquivo binário')
crypto_mode_button = customtkinter.CTkSegmentedButton(root, values=['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'XTS'], variable=chipher_method)
key_size_button = customtkinter.CTkSegmentedButton(root, values=['128', '256'], variable=key_size)
hl = '____________________________________________________________'
hl1 = customtkinter.CTkLabel(root, text=hl, text_color="#2b2b2b")
crypto_labels = customtkinter.CTkLabel(root, text='Mensagens criptografadas:')
hl2 = customtkinter.CTkLabel(root, text=hl, text_color="#2b2b2b")
buttom_clear = customtkinter.CTkButton(root, command=clear_labels, text='Limpar saídas')
buttom_rm_files = customtkinter.CTkButton(root, command=clear_files, text='Remover arquivos')

textbox.pack(pady=10, padx=20)
button_code.pack(pady=10, padx=0)
button_input.pack(pady=10, padx=0)
button_file_text.pack(pady=10, padx=20)
button_file_bin.pack(pady=10, padx=20)
crypto_mode_button.pack(pady=10, padx=20)
key_size_button.pack(padx=20)
buttom_clear.pack(padx=20, pady=20)
buttom_rm_files.pack(padx=20)
hl1.pack(padx=20)
crypto_labels.pack(padx=20)
hl2.pack(padx=20)
scrollable_frame.pack(side=BOTTOM, fill=X)

root.mainloop()
