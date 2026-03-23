import socket
import struct

def get_protocol_name(protocol_num):
    if protocol_num == 1:
        return "ICMP"
    elif protocol_num == 6:
        return "TCP"
    elif protocol_num == 17:
        return "UDP"
    else:
        return "Other"

def main():
    host = socket.gethostbyname(socket.gethostname())

    print("Starting Basic Network Sniffer...")
    print("Host IP Address:", host)
    print("-" * 50)

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        print("Run this program as Administrator.")
        return
    except Exception as e:
        print("Error:", e)
        return

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)

            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 15
            ttl = iph[5]
            protocol_num = iph[6]
            src = socket.inet_ntoa(iph[8])
            dest = socket.inet_ntoa(iph[9])

            protocol_name = get_protocol_name(protocol_num)

            print("\nPacket Captured")
            print("Version:", version)
            print("Header Length:", ihl * 4, "bytes")
            print("TTL:", ttl)
            print("Protocol:", protocol_name)
            print("Source IP:", src)
            print("Destination IP:", dest)
            print("-" * 50)

    except KeyboardInterrupt:
        print("\nStopping sniffer...")
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("Sniffer stopped successfully.")

if __name__ == "__main__":
    main()