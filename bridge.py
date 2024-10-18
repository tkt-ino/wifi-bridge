from scapy.all import *
from libwifi import MonitorSocket

iface: str = "wlan0"
socket = MonitorSocket(type=ETH_P_ALL, iface=iface)
while True:
    try:
        p = socket.recv()
        if p.haslayer(Dot11CCMP): print(p.summary())
    except KeyboardInterrupt:
        break
    
socket.close()

