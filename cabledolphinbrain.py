import os,sys,pyshark
from time import sleep
from termcolor import colored,cprint

HTTP=[0,0]
HTTPS=[0,0]

def incrsrc(port):
    if port == "80":
        HTTP[0]+=1
    elif port == "443":
        HTTPS[0]+=1
def incrdst(port):
    if port == "80":
        HTTP[1]+=1
    elif port =="443":
        HTTPS[1]+=1

def capture():
    capture = pyshark.LiveCapture(interface='eth0')
        for packet in capture.sniff_continuously():
            try:
                incrsrc(packet["TCP"].srcport)
                incrdst(packer["TCP"].dstport)
            except:
                pass
