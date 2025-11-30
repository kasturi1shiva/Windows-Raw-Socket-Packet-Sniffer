import socket
import struct

print("=== Windows Raw Socket Packet Sniffer ===")
print("Press CTRL + C to stop.\n")

# Create a raw socket
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

host = socket.gethostbyname(socket.gethostname())

# Bind to local machine
sniffer.bind((host, 0))

# Include IP headers
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Enable promiscuous mode (Windows only)
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

def decode_ip_header(packet):
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4

    ttl = iph[5]
    protocol = iph[6]
    src = socket.inet_ntoa(iph[8])
    dst = socket.inet_ntoa(iph[9])

    return version, ttl, protocol, src, dst

while True:
    packet, _ = sniffer.recvfrom(65565)

    version, ttl, protocol, src_ip, dst_ip = decode_ip_header(packet)

    if protocol == 1:
        proto_name = "ICMP"
    elif protocol == 6:
        proto_name = "TCP"
    elif protocol == 17:
        proto_name = "UDP"
    else:
        proto_name = "OTHER"

    print("\n📦 Packet Captured:")
    print(f"   Source IP      : {src_ip}")
    print(f"   Destination IP : {dst_ip}")
    print(f"   Protocol       : {proto_name}")

# Disable promiscuous mode when stopping
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
