from getch import getch



a=getch()
print(a)
file=open("boa.txt","w")
file.write(a)
file.close()
