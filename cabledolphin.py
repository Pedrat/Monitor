import os,sys,scapy,pyshark,shutil
import cabledolphinbrain as cdb
from getch import getch
from time import sleep
from threading import Thread as th
from termcolor import colored,cprint
#os.system("clear")
obj=cdb.CAPTURE()
obj.thread()
#while obj.valida == True:



while 1:

    #a=getch()
    opc=input()
    if opc == "1":
        print(colored("Bom dia crlh","red"))
        #if a == "^[":
        #    valida=False
        #    #sys.exit(0)
        #    print(colored(a,'red'),"CARALHO")
