import os,sys,pyshark
from getch import getch
from time import sleep
from termcolor import colored,cprint
from threading import Thread as th



class CAPTURE:
    def __init__(self):
        self.HTTP=[0,0]
        self.HTTPS=[0,0]
        self.valida=True
    def incrsrc(self,port):
        if port == "80":
            self.HTTP[0]+=1
        elif port == "443":
            self.HTTPS[0]+=1
    def incrdst(self,port):
        if port == "80":
            self.HTTP[1]+=1
        elif port =="443":
            self.HTTPS[1]+=1

    def capture(self):
        while self.valida == True:
            capture = pyshark.LiveCapture(interface='eth0')
            for packet in capture.sniff_continuously():
                try:
                    self.incrsrc(packet["TCP"].srcport)
                    self.incrdst(packet["TCP"].dstport)
                except:
                    pass


    def thread(self):
        thr=th(target=self.capture)
        thr.daemon=True
        thr.start()
