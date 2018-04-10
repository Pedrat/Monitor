import os,sys,scapy,pyshark,cabledolphinbrain
from time import sleep
from threading import Thread as th
from termcolor import colored,cprint
os.system("clear")
httprq=0
httpsrq=0
httprp=0
httpsrp=0
capture = pyshark.LiveCapture(interface='eth0')
for packet in capture.sniff_continuously():
    sleep(0.001)
    os.system("clear")
    print("HTTP Request {}\nHTTP Response {}\nHTTPS Request {}\nHTTPS Response {}\n".format(httprq,httprp,httpsrq,httpsrp))
    try:
        #print(packet["TCP"].dstport)#.dst)
        if packet["TCP"].dstport == "80":
            httprp+=1
            #print(colored("HTTP Response","cyan"))
        elif packet["TCP"].dstport == "443":
            httpsrp+=1
            #print (colored('HTTPS Response',"blue"))
        elif packet["TCP"].srcport == "80":
            httprq+=1
            #print (colored('HTTP Request',"yellow"))
        elif packet["TCP"].srcport == "443":
            httprq+=1
            #print (colored('HTTPS Request',"red"))
    except:
        pass
