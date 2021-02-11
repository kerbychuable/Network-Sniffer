# NSCOM03 - S12 AY20-21 T1
# Network Sniffer Tool
# Group 2
# Members:
#   CHUA, Kerby
#   LOPEZ, Earth

import os
import argparse
from argparse import RawTextHelpFormatter
from scapy.all import *
from tabulate import tabulate

def clrscr():
  if os.name == 'nt': # Windows OS
    os.system('cls')
  else: # Non-Windows
    os.system('clear')

def main(argv):
  parser = argparse.ArgumentParser(prog="NetSniff", formatter_class=RawTextHelpFormatter, description=""
                                  + "ARP Scan: 'sudo python3 main.py -arp -ip [IP subnetwork]'\n"
                                  + ""
                                  + "")

  arp_scan = parser.add_argument_group('ARP Scanning')
  arp_scan.add_argument('-arp', '--arp-scan', action="store_true", help="Scan Address Resolution Protocol to see connected devices to network")
  arp_scan.add_argument('-ip', default="", help="Target IP subnetwork")

  args = parser.parse_args()
  if("-arp" in argv) or ("--arp-scan" in argv):
    # target_ip = input("Input IP range for scanning (e.g. 192.168.0.1/24): ")
    # ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=5) # store answered and unanswered packets
    if args.ip == "":
      print("Please specify target IP subnetwork")
      print("usage: sudo python3 main.py -arp -ip [IP subnetwork]")
      sys.exit(0)
    else:
      ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=args.ip), timeout=5) # store answered and unanswered packets
      if not ans: # no devices found
        print("ARP scan did not receive any response")
      else:
        clients = []
        for s, r in ans:
          clients.append({'IP Address': r.psrc, 'MAC Address': r.hwsrc})
        print(tabulate(clients, headers="keys", tablefmt="psql"))

if __name__ == "__main__":
  main(sys.argv[1:])