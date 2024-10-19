from scapy.all import *
from libwifi import *
import subprocess

class Bridge:
    def __init__(
            self,
            apmac: str,
            clientmac: str,
            real_nic: str,
            rouge_nic: str,
            real_ch: int,
            rouge_ch: int,
        ) -> None:
        self.apmac = apmac
        self.clientmac = clientmac
        self.real_nic = real_nic
        self.rouge_nic = rouge_nic
        self.real_ch = real_ch
        self.rouge_ch = rouge_ch

        self.real_nic_mon = real_nic + "mon"
        self.rouge_nic_mon = rouge_nic + "mon"

        self.real_sock = None
        self.rouge_sock = None
    
    def init_socket(self) -> None:
        log(STATUS, f"Initialize sockets. real:{self.real_nic_mon}, rouge:{self.rouge_nic_mon}")
        self.real_sock = MonitorSocket(type=ETH_P_ALL, iface=self.real_nic_mon)
        self.rouge_sock = MonitorSocket(type=ETH_P_ALL, iface=self.rouge_nic_mon)

    def set_bpf_filter(self) -> None:
        log(STATUS, "Set BPF filter.")
        # AP => Client
        real_bpf = f"(wlan type data) and (wlan addr1 {self.clientmac}) and (wlan addr2 {self.apmac})"
        self.real_sock.attach_filter(real_bpf)
        
        # Client => AP
        rouge_bpf = f"(wlan type data) and (wlan addr1 {self.apmac}) and (wlan addr2 {self.clientmac})"
        self.rouge_sock.attach_filter(rouge_bpf)

    def handle_rx_real_ch(self) -> None:
        """
        AP -> Client
        """
        packet = self.real_sock.recv()
        if packet == None: return
        if Dot11CCMP not in packet: return
        self.rouge_sock.send(packet)

    def handle_rx_rouge_ch(self) -> None:
        """
        Client -> AP
        """
        packet = self.real_sock.recv()
        if packet == None: return
        if Dot11CCMP not in packet: return
        self.real_sock.send(packet)

    def start(self) -> None:
        self.init_socket()
        self.set_bpf_filter()
        log(STATUS, "Bridge starting...")
        while True:
            sel = select.select([self.rouge_sock, self.real_sock], [], [], 0.1)
            if self.rouge_sock in sel[0]: self.handle_rx_rouge_ch()
            if self.real_sock in sel[0]: self.handle_rx_real_ch()

    def stop(self) -> None:
        if self.real_sock: self.real_sock.close()
        if self.rouge_sock: self.rouge_sock.close()
        log(STATUS, "Close sockets")

    def airmon_ng_check_kill(self):
        cmd = ["airmon-ng", "check", "kill"]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)
    
    def airmon_ng_start(self, iface: str, channel: str):
        cmd = ["airmon-ng", "start", iface, channel]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, check=True)

def cleanup(bridge_obj: Bridge) -> None:
    bridge_obj.stop()

if __name__ == "__main__":
    bridge = Bridge("00:01:02:03:04:05", "ff:ff:ff:ff:ff:ff", "wlan0", "wlan1", 1, 11)
    atexit.register(cleanup, bridge_obj=bridge)
    bridge.start()