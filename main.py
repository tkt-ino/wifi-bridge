import argparse
import atexit
from bridge import Bridge

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("apmac", help="MAC address of the AP")
    parser.add_argument("clientmac", help="MAC address of the client")
    parser.add_argument("real_nic", help="Wireless monitor interface that listens on the channel of the target AP")
    parser.add_argument("rouge_nic", help="Wireless monitor interface that listens on the channel of the rouge client")
    parser.add_argument("real_ch", help="Channel of the target AP")
    parser.add_argument("rouge_ch", help="Channel of the rouge client")
    args = parser.parse_args()

    args.apmac = args.apmac.lower()
    args.clientmac = args.clientmac.lower()

    bridge = Bridge(args.apmac, args.clientmac, args.real_nic, args.rouge_nic, args.real_ch, args.rouge_ch)
    atexit.register(bridge.stop)
    bridge.start()

if __name__ == "__main__":
    main()
