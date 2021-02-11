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
iface = ""
count = None
fileName = None
verbose = False
pktCount = 0;
results = []

protocols = {
  1: "(ICMP)",
  2: "(IGMP)",
  3: "Gateway-to-Gateway Protocol",
  4: "IP in IP Encapsulation",
  6: "(TCP)",
  17: "(UDP)",
  47: "General Routing Encapsulation (PPTP data over GRE)",
  51: "(AH) IPSec",
  50: "(ESP) IPSec",
  8: "(EGP)",
  3: "Gateway-Gateway Protocol (GGP)",
  20: "Host Monitoring Protocol (HMP)",
  88: "(IGMP)",
  66: "MIT Remote Virtual Disk (RVD)",
  89: "OSPF Open Shortest Path First",
  12: "PARC Universal Packet Protocol (PUP)",
  27: "Reliable Datagram Protocol (RDP)",
  89: "Reservation Protocol (RSVP) QoS"
}

service_guesses = {
  21: "FTP",
  22: "SSH",
  23: "TELNET",
  25: "SMTP",
  53: "DNS",
  67: "DHCP",
  68: "DHCP",
  80: "HTTP",
  110: "POP3",
  115: "Simple File Transfer Protocol",
  118: "SQL Services",
  123: "NTP",
  137: "NetBIOS Name Service",
  138: "NetBIOS Datagram Service",
  139: "NetBIOS Session Service",
  143: "IMAP",
  152: "Background File Transfer Protocol (BFTP)",
  156: "SQL Services",
  161: "SNMP",
  194: "IRC",
  199: "SNMP Multiplexing (SMUX)",
  220: "IMAPv3",
  280: "http-mgmt",
  389: "LDAP",
  443: "HTTPS",
  464: "Kerb password change/set",
  500: "ISAKMP/IKE",
  513: "rlogon",
  514: "rshell",
  520: "RIP",
  530: "RPC",
  543: "klogin, Kerberos login",
  544: "kshell, Kerb Remote shell",
  3306: "MySQL",
  5432: "PostgreSQL",
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
  if verbose:
      pkt.show()

  p = pkt[0][1]

  try:
      proto_name = protocols[pkt.proto]
  except:
      proto_name = "(unknown)"

  svc_guess_local = decode_protocol(p)
  svc_guess_remote = decode_protocol(p, False)

  if svc_guess_remote and svc_guess_remote in ["IMAP","POP3","SMTP"]:
      if verbose:
          print ("[+] Checking for mail creds")
      mail_creds(pkt)
  elif ARP in pkt:
      if verbose:
          print ("[+] ARP packet being sent to ARP specific function")
      arp_display(pkt)

  results.append({'No': pktCount, 'Protocol': proto_name, 'Src IP': p.src, 'Src MAC': str(pkt.src), 'Src Service': svc_guess_local, 'Dest IP': p.dst, 'Dest MAC': str(pkt.dst), 'Dest Service': svc_guess_remote})
  #return "[%s] %s Packet: IP:%s  MAC:%s (%s) ==> IP:%s  MAC:%s (%s)" % (pktCount, proto_name, p.src, str(pkt.src), svc_guess_local, p.dst, str(pkt.dst), svc_guess_remote)

# decodes service protocol via ports used by a packet
# (Reference : https://gist.github.com/dreilly369/a9b9f7e6de96b2cef728bd04527c1ceb)
def decode_protocol(pkt, local=True):
  if local:
      try:
          if pkt.sport in service_guesses.keys():
              srvc_guess = service_guesses[pkt.sport]
          else:
              srvc_guess = str(pkt.sport)
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
  parser = argparse.ArgumentParser(prog="NetSniff", formatter_class=RawTextHelpFormatter, description=""
                                  + "ARP Scan: 'sudo python3 main.py -arp -ip [IP subnetwork]'\n"
                                  + ""
                                  + "")

  arp_scan = parser.add_argument_group('ARP Scanning')
  arp_scan.add_argument('-arp', '--arp-scan', action="store_true", help="Scan Address Resolution Protocol to see connected devices to network")
  arp_scan.add_argument('-ip', default="", help="Target IP subnetwork")

  sniffer = parser.add_argument_group('Packet Sniffing')
  sniffer.add_argument('-sniff', action="store_true", help="Sniff network packets")
  sniffer.add_argument("-i", "--iface", dest="iface",default=None, help="Specify network interface to bind to")
  sniffer.add_argument("-c", "--count", dest="count",default=None, help="specify number of packets to be captured [default: X]")
  sniffer.add_argument("-o", "--outfileName", dest="fileName", default=None, help="Specify name for dump file (w/ extension .pcap)")
  sniffer.add_argument("-v", "--verbose", dest="verb", action="store_true", default=False, help="Display packet contents verbosely")

  args = parser.parse_args()

  if args.iface:
    iface = args.iface.strip()
  if args.fileName:
    outfile = args.fileName

  if args.verb:
    verbose =True

  # ARP Scan
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

  # Network Sniffing
  elif args.sniff:
        
    target = iface or "all interfaces"
    print ("Capturing packets on: %s" % target)

    if args.count:
        limit = int(args.count)
        print ("Capture Limit: %d packets" % limit)
        packets = sniff(iface=iface, prn=packet_recv, count=limit)
        # write out the captured packets

        print ("Writing packets to %s" % outfile)
        wrpcap(outfile, packets)
    else:
        sniff(iface=iface, prn=packet_recv, store=0)
    
    print(tabulate(results, headers="keys", tablefmt="psql"))
    
def KeyboardInterruptHandler(signal, frame):
  print("Goodbye!")
  sys.exit(0)

if __name__ == "__main__":
  signal.signal(signal.SIGINT, KeyboardInterruptHandler)
  main(sys.argv[1:])