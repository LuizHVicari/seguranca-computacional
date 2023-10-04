# Verificação da identidade de um par de comunicações usando HTTPS e X.509
# O X.509 pode ser usado para que o server verifique a identidade do cliente no momento da conexão

# X.509: formato do certificado
# SHA256: algoritmo de hash
# -days 3650: tempo de validade do certificado
# -newkey rsa:4096: criação de uma chave privada RSA de 4096 bits
# -keyout rootCA.key: chave privada
# -out rootCA.crt: certificado

openssl req -x509 -sha256 -days 365 -newkey rsa:4096 -keyout rootCA.key -out rootCA.crt
