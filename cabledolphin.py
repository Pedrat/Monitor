import os,sys,scapy,pyshark
import cabledolphinbrain as cdb
from time import sleep
from threading import Thread as th
from termcolor import colored,cprint
#os.system("clear")
obj=cdb.CAPTURE()
obj.thread()
while obj.valida == True:
    #sleep(2)
    os.system("clear")
    print(obj.HTTP,"\n",obj.HTTPS)



def input():
    #while 1:
    a=getch()
        #if a == "^[":
        #    valida=False
        #    #sys.exit(0)
        #    print(colored(a,'red'),"CARALHO")
