from scan import Scan
from argparse import ArgumentParser

def main():
    parser = ArgumentParser()
    parser.add_argument("ssid", type=str, help="Name of network")
    parser.add_argument("iface", type=str, help="Name of interface")
    args = parser.parse_args()

    scanner = Scan(args.ssid, args.iface)
    scanner.scan_network()
    scanner.scan_clients()

if __name__ == "__main__":
    main()
