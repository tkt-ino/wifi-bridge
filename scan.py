from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
from scapy.sendrecv import sniff
from dataclasses import dataclass
import os
import logs

logger = logs.get_module_logger(__name__)

@dataclass
class Scan:
	ssid: str
	iface: str
	bssid: str = None
	client: str = None
	operate_ch: int = None
	beacon: Dot11Beacon = None
	
	def check_packet(self, packet, channel) -> bool:
		if not packet.haslayer(Dot11Beacon): return False
		if (packet[Dot11Elt].info.decode() != self.ssid): return False
		if (packet[Dot11Beacon].network_stats().get("channel") != channel): return False
		return True

	def change_channel(self, channel) -> None:
		os.system(f"iw dev {self.iface} set channel {channel}")	
		logger.debug(f"interface {self.iface} is running on channel {channel}")

	def scan_network(self):
		logger.info("Scanning network...")
		for ch in range(1, 15):
			self.change_channel(ch)
			packets = sniff(count=10, iface=self.iface, filter="(wlan type mgt) and (wlan subtype beacon)", timeout=3)
			for packet in packets:
				if (not self.check_packet(packet, ch)): continue
				self.bssid = packet[Dot11].addr2
				self.operate_ch = ch
				self.beacon = packet[Dot11Beacon]

				logger.info(f"{self.ssid} ({self.bssid}) found on channel {self.operate_ch}")
				return

		logger.warning(f"network {self.ssid} not found")
	
	def scan_clients(self):
		if None in [self.bssid, self.operate_ch]: 
			logger.warning("Network scan has not been done")
			return

		logger.info("Scanning clients...")
		self.change_channel(self.operate_ch)

		packet = sniff(count=1, iface=self.iface, filter=f"(wlan type data) and (wlan addr1 {self.bssid})", timeout=10)
		if (len(packet) < 1): 
			logger.warning("Clients not found")
			return

		self.client = packet[0].addr2
		logger.info(f"Client ({self.client}) found")

	def result(self):
		if self.bssid is None: return
		if self.operate_ch is None: return
		logger.info(f"network {self.ssid} ({self.bssid}) is on channel {self.operate_ch}")
