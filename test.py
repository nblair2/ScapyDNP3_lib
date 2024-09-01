from scapy.all import *
from DNP3_Lib import *

for p in rdpcap('data/dnp3_read.pcap'):
    if p.haslayer(DNP3):
        p[DNP3].show2()
