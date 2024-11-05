from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from scapy.sendrecv import sniff
import os
import logs

logger = logs.get_module_logger(__name__)

class Scan:
	def __init__(self, ssid: str, iface: str):
		self.ssid = ssid
		self.iface = iface
		self.bssid = None
		self.found_ch = None
	
	def check_packet(self, packet, channel) -> bool:
		if not packet.haslayer(Dot11Beacon): return False
		if (packet[Dot11Elt].info.decode() != self.ssid): return False
		if (packet[Dot11Beacon].network_stats().get("channel") != channel): return False
		logger.info(f"{self.ssid} found at channel {channel}")
		return True

	def change_channel(self, channel) -> None:
		os.system(f"iw dev {self.iface} set channel {channel}")	
		logger.debug(f"interface {self.iface} is running on channel {channel}")

	def run(self):
		for ch in range(1, 15):
			self.change_channel(ch)
			packets = sniff(count=10, iface=self.iface, filter="(wlan type mgt) and (wlan subtype beacon)", timeout=3)
			for packet in packets:
				if (not self.check_packet(packet, ch)): continue
				self.bssid = packet[Dot11].addr2
				self.found_ch = ch
				return
		logger.warning(f"network {self.ssid} not found")

	def result(self):
		if self.bssid is None: return
		if self.found_ch is None: return
		logger.info(f"network {self.ssid} ({self.bssid}) is on channel {self.found_ch}")
