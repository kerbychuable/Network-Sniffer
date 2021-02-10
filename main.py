# NSCOM03 - S12 AY20-21 T1
# Network Sniffer Tool
# Group 2
# Members:
#   CHUA, Kerby
#   LOPEZ, Earth

import os
from scapy.all import *
from tabulate import tabulate

def clrscr():
  if os.name == 'nt': # Windows OS
    os.system('cls')
  else: # Non-Windows
    os.system('clear')

if __name__ == "__main__":
  target_ip = input("Input IP range for scanning (e.g. 192.168.0.1/24): ")
  ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=5) # store answered and unanswered packets
  clrscr()
  clients = []
  for s, r in ans:
    clients.append({'IP Address': r.psrc, 'MAC Address': r.hwsrc})

  print(tabulate(clients, headers="keys", tablefmt="psql"))
  os.system('pause')