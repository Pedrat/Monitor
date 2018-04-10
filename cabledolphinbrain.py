import os,sys,pyshark,shutil
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
    def menu(self):
        while 1:
            sleep(0.2)
            os.system("clear")
            columns=shutil.get_terminal_size().columns
            lines="\n"*((shutil.get_terminal_size().lines//2)-2)
            print(lines)
            maior= max((len(str(self.HTTP[0]))),(len(str(self.HTTP[1]))),(len(str(self.HTTPS[0]))),(len(str(self.HTTPS[1]))))
            esc=" "*(maior-1)
            #if len(str(self.HTTP[0])) == maior:

            print(("||"+esc+str(self.HTTP[0])+"||"+str(self.HTTP[1])+esc+"||").center(columns))
            print(("||"+esc+str(self.HTTPS[0])+"||"+str(self.HTTPS[1])+esc+"||").center(columns))
        #    print(self.HTTPS.center(columns))


    def thread(self):
        thr=th(target=self.capture)
        thr.daemon=True
        thr.start()
        thr2=th(target=self.menu)
        thr2.daemon=True
        thr2.start()
