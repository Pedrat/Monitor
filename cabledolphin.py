import os,sys,scapy,pyshark
from time import sleep
from threading import Thread as th
from termcolor import colored,cprint
os.system("clear")

capture = pyshark.LiveCapture(interface='eth0')
capture.sniff(timeout=50)
print(capture)
