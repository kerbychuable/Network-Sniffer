# NSCOM03 - S12 AY20-21 T1
# Network Sniffer Tool
# Group 2
# Members:
#   CHUA, Kerby
#   LOPEZ, Earth

from scapy.all import ARP, Ether, srp

if __name__ == "__main__":
  target_ip = "192.168.1.1/24"
  ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=5)
  ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%"))