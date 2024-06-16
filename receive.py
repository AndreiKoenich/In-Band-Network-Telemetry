#!/usr/bin/env python3
import os
import sys

TYPE_IPV4 = 0x800
TYPE_INT_PAI = 0x1212

TAMANHO_INT_PAI_BYTES = 8
TAMANHO_INT_FILHO_BYTES = 13

from scapy.all import (
    Ether,
    Packet,
    IP,
    TCP,
    FieldLenField,
    FieldListField,
    BitField,
    IntField,
    LongField,
    LEIntField,
    IPOption,
    ShortField,
    sniff,
    bind_layers,
    hexdump
)
from scapy.layers.inet import _IPOption_HDR

class IntPai(Packet):
    name = "IntPai"
    fields_desc = [
        IntField("Tamanho_Filho", 0),
        IntField("Quantidade_Filhos", 0)
    ]

class IntFilho(Packet):
    name = "IntFilho"
    fields_desc = [
        ShortField("ID_Switch", 0),
        ShortField("Porta_Entrada", 0),
        ShortField("Porta_Saida", 0),
        ShortField("Timestamp", 0),
        ShortField("Padding", 0)
    ]

# Bind dos cabeçalhos
bind_layers(Ether, IP)
bind_layers(IP, TCP)
bind_layers(TCP, IntPai) # TCP para IntPai
#bind_layers(IntPai, IntFilho) # TCP para IntPai

def bytes_to_bits_binary(byte_data):
    # Calcula o número total de bits com base no comprimento dos bytes de entrada
    total_bits = len(byte_data) * 8
    # Converte os bytes para um inteiro, depois para uma string binária
    bits_data = bin(int.from_bytes(byte_data, byteorder='big'))[2:]
    # Adiciona zeros à esquerda para garantir que o comprimento da string binária seja igual ao número total de bits
    bits_data = bits_data.zfill(total_bits)
    return bits_data

def handle_pkt(pkt):

    eth_header = pkt[Ether]

    if eth_header.type == TYPE_INT_PAI:
        # Imprime o cabeçalho Ethernet
        print("\n###[ Ethernet ]###\n")
        print(f"\tdst = {eth_header.dst}")
        print(f"\tsrc = {eth_header.src}")
        print(f"\ttype=  {hex(eth_header.type)}\n")

        # Imprime o cabeçalho IP
        ip_header = pkt[IP]
        print("###[ IP ]###")
        print(f"\tversion = {ip_header.version}")
        print(f"\tihl = {ip_header.ihl}")
        print(f"\ttos = {ip_header.tos}")
        print(f"\tlen = {ip_header.len}")
        print(f"\tid = {ip_header.id}")
        print(f"\tflags = {ip_header.flags}")
        print(f"\tfrag = {ip_header.frag}")
        print(f"\tttl = {ip_header.ttl}")
        print(f"\tproto = {ip_header.proto}")
        print(f"\tchksum = {hex(ip_header.chksum)}")
        print(f"\tsrc = {ip_header.src}")
        print(f"\tdst = {ip_header.dst}")

        # Imprime o cabeçalho TCP
        tcp_header = pkt[TCP]
        print("\n###[ TCP ]###\n")
        print(f"\tsport = {tcp_header.sport}")
        print(f"\tdport = {tcp_header.dport}")
        print(f"\tseq = {tcp_header.seq}")
        print(f"\tack = {tcp_header.ack}")
        print(f"\tdataofs = {tcp_header.dataofs}")
        print(f"\treserved = {tcp_header.reserved}")
        print(f"\tflags = {tcp_header.flags}")
        print(f"\twindow = {tcp_header.window}")
        print(f"\tchksum = {hex(tcp_header.chksum)}")
        print(f"\turgptr = {tcp_header.urgptr}")

        # Imprime o cabeçalho IntPai
        tcp_payload = bytes(tcp_header.payload)
        tamanho_filho = int.from_bytes(tcp_payload[:4], byteorder='big')
        quantidade_filhos = int.from_bytes(tcp_payload[4:8], byteorder='big')

        print("\n###[ IntPai ]###\n")
        print(f"\tTamanho_Filho = {tamanho_filho}")
        print(f"\tQuantidade_Filhos = {quantidade_filhos}")

        # Imprime os cabeçalhos IntFilho
        tcp_payload_filhos = tcp_payload[TAMANHO_INT_PAI_BYTES:]
        for index in range (0,quantidade_filhos):

            limite_inferior_bytes = index*TAMANHO_INT_FILHO_BYTES
            limite_superior_bytes = (index+1)*TAMANHO_INT_FILHO_BYTES
            bits_filho = bytes_to_bits_binary(tcp_payload_filhos[limite_inferior_bytes:limite_superior_bytes])

            print("\n###[ IntFilho - SWITCH", int(bits_filho[:32],2),"]###\n")
            print(f"\tID_Switch = {int(bits_filho[:32],2)}")
            print(f"\tPorta_entrada = {int(bits_filho[32:41],2)}")
            print(f"\tPorta_saida = {int(bits_filho[41:50],2)}")
            print(f"\tTimestamp = {int(bits_filho[50:98],2)}")

        print("\n###[ Payload ]###\n")
        payload_final = tcp_payload[(TAMANHO_INT_PAI_BYTES+(TAMANHO_INT_FILHO_BYTES*quantidade_filhos)):]
        hexdump(payload_final)

        sys.stdout.flush()

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
