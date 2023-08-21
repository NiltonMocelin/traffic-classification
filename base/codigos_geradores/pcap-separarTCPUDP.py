#pegar um pcap e filtrar apenas pacotes TCP/UDP

#algoritmo para contar o tamanho dos pacotes e a quantidade deles, juntamente com o tempo total ativo e o maior tempo 

#Modos de finalizar uma conexao tcp:  https://www.baeldung.com/cs/tcp-ip-reset-flag

#https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html
#features: Protocol,Timestamp,Flow.Duration,Total.Length.of.Fwd.Packets.Packets,Fwd.Packet.Length.Max,Fwd.Packet.Length.Min,Fwd.Packet.Length.Mean,Fwd.Packet.Length.Std,
# Flow.Bytes.s,Flow.Packets.s,Flow.IAT.Mean,Flow.IAT.Std,Flow.IAT.Max,Flow.IAT.Min,Fwd.IAT.Total,Fwd.IAT.Mean,Fwd.IAT.Std,Fwd.IAT.Max,Fwd.IAT.Min,
# Fwd.PSH.Flags,Fwd.URG.Flags,Fwd.Header.Length,Fwd.Packets.s,Packet.Length.Variance,FIN.Flag.Count,SYN.Flag.Count,RST.Flag.Count,PSH.Flag.Count,
# ACK.Flag.Count,URG.Flag.Count,CWE.Flag.Count,ECE.Flag.Count,Down.Up.Ratio,Average.Packet.Size,Avg.Fwd.Segment.Size,Fwd.Header.Length.1,
# Fwd.Avg.Bytes.Bulk,Fwd.Avg.Packets.Bulk,Fwd.Avg.Bulk.Rate,Subflow.Fwd.Packets,Subflow.Fwd.Bytes,Init_Win_bytes_forward,act_data_pkt_fwd,
# min_seg_size_forward,Active.Mean,Active.Std,Active.Max,Active.Min,Idle.Mean,Idle.Std,Idle.Max,Idle.Min
# Label,L7Protocol,ProtocolName

import argparse
import os
import sys
import time
import datetime

# from scapy.utils import RawPcapReader
# from scapy.utils import rdpcap
from scapy.all import *

#TCP FLAGS
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def timestamp(dt):
    epoch = datetime.utcfromtimestamp(0)
    return (dt - epoch).total_seconds() * 1000.0

def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    pcaps = rdpcap(file_name)

    #armazenar a tupla (tamanho_bytes, time, proto, flags)
    lista_tamanhos=[]
    lista_largurabanda = []
    largurabanda = 0.0

    contador_pkts = 0

    pkti_time = None

    menor_pkt = 10000.0
    maior_pkt = 0.0

    #tempo para que uma regra de fluxo expire por inatividade
    idle_timeout = 5.0
    
    #o pktfinal eh o atual
    #pktf_timestamp = None
    # pktanterior_timestamp = None
    newfile_name = "tcpudp_"+file_name
    
    for pkt in pcaps:

        if(pkt.haslayer(IP) == False and (pkt.haslayer(UDP) == False or pkt.haslayer(TCP) == False)) :
            continue

        #escrever pacote
        pktdump = RawPcapWriter(newfile_name, append=True)
        # pktdump = wrpcap(newfile_name, pkt, append=True)

        pktdump.write(pkt)

    print("arquivo gerado: {}".format(newfile_name))
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)

# summary() displays a list of summaries of each packet
# nsummary() same as previous, with the packet number
# conversations() displays a graph of conversations
# show() displays the prefered representation (usually
# nsummary())
# filter() returns a packet list filtered with a lambda function
# hexdump() returns a hexdump of all packets
# hexraw() returns a hexdump of the Raw layer of all packets
# padding() returns a hexdump of packets with padding
# nzpadding() returns a hexdump of packets with non-zero
# padding
# plot() plots a lambda function applied to the packet list
# make table() displays a table according to a lambda function
# Philippe BIONDI Network packet manipul



#printar tempo de chegada de um pacote

# print('First packet in connection: Packet #{} {}'.
#           format(first_pkt_ordinal,
#                  printable_timestamp(first_pkt_timestamp,
#                                      first_pkt_timestamp_resolution)))

# import time

# def printable_timestamp(ts, resol):
#     ts_sec = ts // resol
#     ts_subsec = ts % resol
#     ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
#     return '{}.{}'.format(ts_sec_str, ts_subsec)


        

        

    # print(lista_tamanhos[0][1])
    # print(lista_tamanhos[1][1])
    # diferenca_tempo = lista_tamanhos[1][1] - lista_tamanhos[0][1]

    # print(diferenca_tempo)

    # print(float(str(diferenca_tempo).split(':')[2]))

    # #verificar se o tempo entre dois pacotes eh maior que 1s para udp
    # if(float(str(diferenca_tempo).split(':')[2]) > 1.0):
    #     print("é diferente kk")
    # else:
    #     print("são iguaiss")