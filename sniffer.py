from scapy.all import *
from scapy_http import http
import string

print("Simple HTTP Sniffer")
iface = input('enter your interface -->')
def packet_process(pkt):
    if pkt.haslayer(http.HTTPRequest):
        print('Request -->', pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path)
        if pkt.haslayer(Raw):
            loader_data = pkt[Raw].load
            print('Data: ', loader_data)

print('sniffing')
sniff(iface=iface, store=False, prn=packet_process)