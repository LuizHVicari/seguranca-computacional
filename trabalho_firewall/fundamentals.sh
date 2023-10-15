# permite ssh de qualquer lugar
iptables -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# -A: append no final da lista
# INPUT: pacotes que chegam
# -i: interface de entrada
# eth0: interface de rede
# -p: protocolo
# tcp: protocolo tcp
# --dport: porta de destino
# 22: porta 22 (ssh)
# -m: modulo
# state: modulo state
# --state: estado do pacote
# NEW: pacote novo
# ESTABLISHED: pacote estabelecido
# -j: jump
# ACCEPT: aceita o pacote

# OUTPUT: pacotes que saem
# -o: interface de saida
# --sport: porta de origem


# permite http de qualquer lugar
iptables -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# 80: porta 80 (http)

# bloqueia ping
iptables -A OUTPUT -p icmp -j DROP
