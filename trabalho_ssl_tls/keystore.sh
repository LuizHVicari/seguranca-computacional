# Um keystore é onde a aplicação guarda a chave privada e o certificado, assim ele pode certificar os clientes

# autenticação server-side
# req: criação de um certificado
# -new: criação de um novo certificado
# -newkey rsa:4096: criação de uma chave privada RSA de 4096 bits
# -keyout localhost.key: chave privada
# -out localhost.csr: certificado

openssl req -new -newkey rsa:4096 -keyout localhost.key -out localhost.csr

openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in localhost.csr -out localhost.crt -days 365 -CAcreateserial -extfile localhost.ext
