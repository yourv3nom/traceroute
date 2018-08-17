import os
import sys
import time
import threading
from threading import Thread
from scapy.all import *

hops = 0

try:
	from colorama import *
except KeyboardInterrupt:
		print "Exiting.."
		time.sleep(1.5)
except:
	try:
		os1 = raw_input("Whats your OS?[debian or centos] --> ")
		if "Debian" in os1 or "debian" in os1:
			os.system("sudo apt-get insall python-pip")
			os.system("sudo pip install colorama")
		if "CentOS" in os1 or "centos" in os1 or "Centos" in os1 or "centOS" in os1:
			os.system("yum install python-pip -y")
			os.system("pip install colorama")
	except KeyboardInterrupt:
		print "Exiting.."
		time.sleep(1.5)

x8 = Style.BRIGHT + Fore.RED + "Router: " + Style.RESET_ALL
x9 = Style.BRIGHT + Fore.CYAN + "Reached Host: " + Style.RESET_ALL
x10 = Style.BRIGHT + Fore.CYAN + "TraceRoute Finished" + Style.RESET_ALL
x11 = Style.BRIGHT + Fore.CYAN + "Press CTRL + C to exit script" + Style.RESET_ALL
x12 = Style.BRIGHT + Fore.RED + "Hops: " + Style.RESET_ALL
x13 = Style.BRIGHT + Fore.CYAN + "Thank you for using trace <3 " + Style.RESET_ALL
x14 = Style.BRIGHT + Fore.CYAN + "Tracing the route to: " + Style.RESET_ALL
x1 = Style.BRIGHT + Fore.RED + " 		 _______                 	" + Style.RESET_ALL
x2 = Style.BRIGHT + Fore.RED + " 		|__   __|                	" + Style.RESET_ALL
x3 = Style.BRIGHT + Fore.RED + "  		   | |_ __ __ _  ___ ___ 	" + Style.RESET_ALL
x4 = Style.BRIGHT + Fore.RED + "  		   | | '__/ _` |/ __/ _ \	" + Style.RESET_ALL
x5 = Style.BRIGHT + Fore.RED + "  		   | | | | (_| | (_|  __/	" + Style.RESET_ALL
x6 = Style.BRIGHT + Fore.RED + "  		   |_|_|  \__,_|\___\___|	" + Style.RESET_ALL
x7 = Style.BRIGHT + Fore.CYAN + " 		    created by @yourv3nom"

def venom():
	os.system("clear")
	print x1
	print x2
	print x3
	print x4
	print x5
	print x6 
	print x7 + "\n"

venom()
interface = raw_input("Whats your interface name? --> ")
trace = raw_input("What host do you want to trace the route to? --> ") 




def yourv3nom(pkt):
	global hops
	if pkt.haslayer("IPerror"):
		if pkt[IP].src == trace:
			print "\n" + x9 + pkt[IP].src 
			sys.exit()
		else:
			print "\n" + x8 + pkt[IP].src
			hops += 1

def traceroute():
	try:
		global yourv3nom
		global hops
		os.system("clear")
		venom()
		print "\n" + x14 + trace
		send(IP(dst = trace, ttl = 1), verbose =False)	
		send(IP(dst = trace, ttl = 2), verbose =False)	
		send(IP(dst = trace, ttl = 3), verbose =False)	
		send(IP(dst = trace, ttl = 4), verbose =False)	
		send(IP(dst = trace, ttl = 5), verbose =False)	
		send(IP(dst = trace, ttl = 6), verbose =False)	
		send(IP(dst = trace, ttl = 7), verbose =False)	
		send(IP(dst = trace, ttl = 8), verbose =False)	
		send(IP(dst = trace, ttl = 9), verbose =False)
		send(IP(dst = trace, ttl = 10), verbose =False)	
		send(IP(dst = trace, ttl = 11), verbose =False)	
		send(IP(dst = trace, ttl = 12), verbose =False)	
		send(IP(dst = trace, ttl = 13), verbose =False)	
		send(IP(dst = trace, ttl = 14), verbose =False)	
		send(IP(dst = trace, ttl = 15), verbose =False)	
		send(IP(dst = trace, ttl = 16), verbose =False)	
		send(IP(dst = trace, ttl = 17), verbose =False)	
		send(IP(dst = trace, ttl = 18), verbose =False)	
		send(IP(dst = trace, ttl = 19), verbose =False)	
		send(IP(dst = trace, ttl = 20), verbose =False)		
		print "\n" + x9 + trace
		print "\n" + x10
		print "\n" + x12 + str(hops) + "\n"
		r = raw_input(x11)
		venom()
		sys.exit()
	except KeyboardInterrupt:
		sys.exit()
		
def main():
	try:
		sniff(iface = interface, prn=yourv3nom)		
	except KeyboardInterrupt:
		sys.exit()

a = threading.Thread(target = traceroute)
a.daemon = True
b = threading.Thread(target = main)
b.daemon = True

if "__main__" in __name__:
	try:
		a.start()
		b.start()
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		venom()
		print "\n" + x13 + "\n" 
		sys.exit()











