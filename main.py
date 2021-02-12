# NSCOM03 - S12 AY20-21 T1
# Network Sniffer Tool
# Group 2
# Members:
#   CHUA, Kerby
#   LOPEZ, Earth

import os
import signal
import argparse
from argparse import RawTextHelpFormatter
from scapy.all import *
from tabulate import tabulate

# Globals
issniffing = False
iface = ""
count = None
fileName = None
verbose = False
pktCount = 0
results = []
services = {'HTTP': 0, 'HTTPS': 0, 'DHCP': 0, 'ARP': 0, 'FTP': 0, 'SMTP': 0, 'POP3': 0, 'SSH': 0, 'TELNET': 0, 'OTHERS' : 0}

protocols = {
  1: "(ICMP)",
  2: "(IGMP)",
  3: "Gateway-to-Gateway Protocol",
  4: "IP in IP Encapsulation",
  6: "(TCP)",
  17: "(UDP)",
  47: "General Routing Encapsulation (PPTP data over GRE)",
  3: "Gateway-Gateway Protocol (GGP)",
  88: "(IGMP)",
  89: "OSPF Open Shortest Path First",
}

service_guesses = {
  20: "FTP",
  21: "FTP",
  22: "SSH",
  23: "TELNET",
  25: "SMTP",
  53: "DNS",
  67: "DHCP",
  68: "DHCP",
  69: "TFTP",
  80: "HTTP",
  110: "POP3",
  115: "Simple File Transfer Protocol",
  443: "HTTPS",
  8080: "HTTP"
}

def clrscr():
  if os.name == 'nt': # Windows OS
    os.system('cls')
  else: # Non-Windows
    os.system('clear')

def mail_creds(pkt):
  if pkt[TCP].payload:
      mail_packet = str(pacpktket[TCP].payload)
      if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
          print ("[+] Server: %s" % pkt[IP].dst)
          print ("[+] %s" % pkt[TCP].payload)

def arp_display(pkt):
  if pkt[ARP].op == 1: #who-has (request)
      return "Request: " + pkt[ARP].psrc + " is asking about " + pkt[ARP].pdst
  if pkt[ARP].op == 2: #is-at (response)
      return "*Response: " + pkt[ARP].hwsrc + " has address " + pkt[ARP].psrc

# identifies service protocols of packets and logs them in a raw file (if specififed)
# (Reference : https://gist.github.com/dreilly369/a9b9f7e6de96b2cef728bd04527c1ceb)
def packet_recv(pkt):
  global pktCount
  global verbose
  global fileName

  pktCount += 1

  # append packet to output file
  if fileName:
      wrpcap(fileName, pkt, append=True)

  p = pkt[0][1]

  try:
      proto_name = protocols[pkt.proto]
  except:
      proto_name = "(unknown)"

  srvc_local = decode_protocol(p)
  srvc_remote = decode_protocol(p, False)
        
  if srvc_remote and srvc_remote in ["IMAP","POP3","SMTP"]:
      mail_creds(pkt)
  elif ARP in pkt:
      arp_display(pkt)

  results.append({'No': pktCount, 'Protocol': proto_name, 'Src IP': p.src, 'Src MAC': str(pkt.src), 'Src Service': srvc_local, 'Dest IP': p.dst, 'Dest MAC': str(pkt.dst), 'Dest Service': srvc_remote})
  print("[%d] %s IP:%s  MAC:%s (%s) ==> IP:%s  MAC:%s (%s)" % (pktCount, proto_name, p.src, str(pkt.src), srvc_local, p.dst, str(pkt.dst), srvc_remote))

# decodes service protocol via ports used by a packet
# (Reference : https://gist.github.com/dreilly369/a9b9f7e6de96b2cef728bd04527c1ceb)
def decode_protocol(pkt, local=True):
  global services
  if local:
    try:
      if pkt.sport in service_guesses.keys():
        srvc_guess = service_guesses[pkt.sport]

        if srvc_guess is 'HTTP':
          services['HTTP'] += 1
        elif srvc_guess is 'HTTPS':
          services['HTTPS'] += 1
        elif srvc_guess is 'DHCP':
          services['DHCP'] += 1
        elif srvc_guess is  'ARP':
          services['ARP'] += 1
        elif srvc_guess is  'FTP':
          services['FTP'] += 1
        elif srvc_guess is 'SMTP':
          services['SMTP'] += 1
        elif srvc_guess is  'POP3':
          services['POP3'] += 1
        elif srvc_guess is 'SSH':
          services['SSH'] += 1
        elif srvc_guess is  'TELNET':
          services['TELNET'] += 1

      else:
        srvc_guess = str(pkt.sport)
        services['OTHERS'] += 1
    except AttributeError:
        srvc_guess = None
  else:
      try:
          if pkt.dport in service_guesses.keys():
              srvc_guess = service_guesses[pkt.dport]
          else:
              srvc_guess = str(pkt.dport)
      except AttributeError:
          srvc_guess = None
  return srvc_guess

def main(argv):
  global iface
  global issniffing

  parser = argparse.ArgumentParser(prog="NetSniff", formatter_class=RawTextHelpFormatter, description=""
                                  + "ARP Scan: 'sudo python3 main.py -arp -ip [IP subnetwork]'\n"
                                  + ""
                                  + "")

  arp_scan = parser.add_argument_group('ARP Scanning')
  arp_scan.add_argument('-arp', '--arp-scan', dest="ip", default=None, help="Scan Address Resolution Protocol to see connected devices to network")

  sniffer = parser.add_argument_group('Packet Sniffing')
  sniffer.add_argument('-sniff', action="store_true", help="Sniff network packets")
  sniffer.add_argument("-i", "--iface", dest="iface", default=None, help="Specify network interface to bind to")
  sniffer.add_argument("-c", "--count", dest="count", default=None, help="specify number of packets to be captured [default: X]")
  sniffer.add_argument("-o", "--outfileName", dest="fileName", default=None, help="Specify name for dump file (w/ extension .pcap)")

  args = parser.parse_args()

  if args.iface:
    iface = args.iface.strip()
  if args.fileName:
    outfile = args.fileName

  # ARP Scan
  if("-arp" in argv) or ("--arp-scan" in argv):
    # target_ip = input("Input IP range for scanning (e.g. 192.168.0.1/24): ")
    # ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=5) # store answered and unanswered packets
    if not args.ip:
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

  # Network Sniffing
  elif args.sniff:
    issniffing = True

    target = iface or "all interfaces"
    print ("Capturing packets on: %s" % target)

    if args.count:
        limit = int(args.count)
        print ("Capture Limit: %d packets" % limit)
        packets = sniff(iface=args.iface, prn=packet_recv, count=limit)
        # write out the captured packets

        print ("\nWriting packets to %s" % outfile)
        wrpcap(outfile, packets)
    else:
        sniff(iface=args.iface, prn=packet_recv, store=0)
    
    clrscr()
    print(tabulate(results, headers="keys", tablefmt="psql"))

    print('Protocols Sniffed Statistics:')
    for srvc, value in services.items():
      print(srvc, ':', value)
    
    
def KeyboardInterruptHandler(signal, frame):
  global services
  if issniffing:
    clrscr()
    print('\n', tabulate(results, headers="keys", tablefmt="psql"))

    print('\nProtocols Sniffed Statistics:')
    for srvc, value in services.items():
      print(srvc, ':', value)
  
  print("Goodbye!")
  sys.exit(0)

if __name__ == "__main__":
  signal.signal(signal.SIGINT, KeyboardInterruptHandler)
  main(sys.argv[1:])