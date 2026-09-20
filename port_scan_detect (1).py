import socket
import struct
import threading
import logging
from collections import defaultdict

# Configuration
INTERFACE = '127.0.0.1'  # Loopback address for local testing
PORT_SCAN_THRESHOLD = 10  # Number of distinct ports to trigger an alert

# Set up logging
logging.basicConfig(filename='port_scan_detection.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_ip_header(packet):
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    protocol = iph[6]
    return src_ip, dst_ip, protocol

def get_tcp_header(packet):
    ip_header_length = (packet[0] & 0x0F) * 4
    tcp_header = packet[ip_header_length:ip_header_length + 20]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    src_port = tcph[0]
    dst_port = tcph[1]
    return src_port, dst_port

def handle_packet(packet, port_scan_count):
    try:
        src_ip, dst_ip, protocol = get_ip_header(packet)
        
        if protocol != socket.IPPROTO_TCP:
            return  # Ignore non-TCP packets
        
        _, dst_port = get_tcp_header(packet)

        if src_ip in port_scan_count:
            port_scan_count[src_ip].add(dst_port)
        else:
            port_scan_count[src_ip] = {dst_port}

        if len(port_scan_count[src_ip]) > PORT_SCAN_THRESHOLD:
            alert_message = f"[ALERT] Port scanning detected from {src_ip} with {len(port_scan_count[src_ip])} distinct ports."
            print(alert_message)
            logging.info(alert_message)
    except Exception as e:
        logging.error(f"Error handling packet: {e}")

def detect_port_scan():
    port_scan_count = defaultdict(set)

    # Create a raw socket to listen for packets
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((INTERFACE, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print("Socket successfully created and bound to interface.")
    except socket.error as e:
        logging.error(f"Socket error: {e}")
        print(f"Socket error: {e}")
        return

    print("Listening for IP packets on interface...")

    while True:
        try:
            packet = sock.recvfrom(65565)[0]
            # Use a separate thread to handle the packet
            threading.Thread(target=handle_packet, args=(packet, port_scan_count)).start()
        except Exception as e:
            logging.error(f"Error receiving packet: {e}")
            print(f"Error receiving packet: {e}")

if __name__ == "__main__":
    detect_port_scan()
