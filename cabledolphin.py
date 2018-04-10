import os,sys,scapy,pyshark
from time import sleep
from threading import Thread as th
from termcolor import colored,cprint
os.system("clear")

capture = pyshark.LiveCapture(interface='eth0')
for packet in capture.sniff_continuously():
    try:
        #print(packet["TCP"].dstport)#.dst)
        if packet["TCP"].dstport == "80":
            print(colored("HTTP Response","cyan"))
        elif packet["TCP"].dstport == "443":
            print (colored('HTTPS Response',"blue"))
        elif packet["TCP"].srcport == "80":
            print (colored('HTTP Request',"yellow"))
        elif packet["TCP"].srcport == "443":
            print (colored('HTTPS Request',"red"))
    except:
        pass
