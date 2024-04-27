# TUPacket: TCP/UDP Packet Spoofer

TUPacket is a Python-based tool that allows you to generate and send TCP or UDP packets with spoofed IP addresses.

## Features

- Generate TCP or UDP packets
- Spoof source IP addresses
- Spam a number of packets at specified intervals
- Log the details of the packets being sent
- Coming Soon: Custom Payload

## Requirements

- Python 3
- Root or administrator privileges (required to create raw sockets)

## Usage
* $ sudo python tup.py -p PROTOCOL -source SOURCE_IP -dest DEST_IP
- Example: Send 10 TCP packets from a random source IP to a destination IP of 192.0.2.0, with a delay of 1 second between each packet, and log it to log.txt:
![Screenshot 2024-04-26 233007](https://github.com/dotslashCosmic/TUPacket/assets/91699202/2751306f-1462-4478-b3eb-4b4f94866759)

- $ sudo python tup.py -p tcp -source random -dest 192.0.2.0 -delay 1000 -count 10 -l log.txt

Required Args:
- -p, --protocol: The protocol to use (tcp or udp).
- -source, --source-ip [CUSTOM]: The source IP address. CUSTOM can be an IP address, 'random' or 'list' for a list of IPs.
- -dest, --dest-ip: The destination IP address.

Optional args:
- -sp, --source-port: The source port (default is 0).
- -dp, --dest-port: The destination port (default is 0).
- -delay, --delay: The delay between packets in milliseconds. Must be used with -count.
- -count, --count: The number of packets to send. Must be used with -delay.
- -l, --log-file [LOG_FILE]: Enables logging. If LOG_FILE is specified, it uses it as the log file name. If LOG_FILE is not specified, generate a log file name based on the current time and destination IP.
