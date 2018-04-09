import os,sys,scapy,pyshark
from time import sleep
from threading import Thread as th
from termcolor import colored,cprint
os.system("clear")

capture = pyshark.LiveCapture(interface='eth0')
for packet in capture.sniff_continuously():
    try:
        print(packet["TCP"].dstport)#.dst)
    except:
        pass
    if "HTTP" in packet:
        print (colored('Just arrived',"white"))
    if "HTTPS" in packet:
        print(colored("Just arrived",'red'))
