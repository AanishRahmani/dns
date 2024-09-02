import argparse
from scapy.all import IP, TCP, send
import pyshark
import threading
import time

# Function to create an IP packet
def create_ip_packet(src_ip, dest_ip):
    return IP(src=src_ip, dst=dest_ip)

# Function to create a TCP packet
def create_tcp_packet(src_ip, dest_ip, sport=12345, dport=80):
    ip_packet = create_ip_packet(src_ip, dest_ip)
    tcp_packet = TCP(sport=sport, dport=dport)
    return ip_packet / tcp_packet

# Function to send crafted packets using Scapy
def send_packets(src_ip, dest_ip, interval=5):
    while True:
        try:
            packet = create_tcp_packet(src_ip, dest_ip)
            send(packet)
            print(f"Sent TCP packet from {src_ip} to {dest_ip}")
            time.sleep(interval)  # Adjust the interval as needed
        except Exception as e:
            print(f"Error sending packet: {e}")

# Function to process captured packets using PyShark
def process_packet(packet):
    try:
        if hasattr(packet, 'ip'):
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            print(f"Captured Packet: Src IP: {ip_src}, Dest IP: {ip_dst}")

            # TCP protocol
            if hasattr(packet, 'tcp'):
                tcp_pkt = packet.tcp
                print(f"TCP Packet: Src Port: {tcp_pkt.srcport}, Dest Port: {tcp_pkt.dstport}")
                if hasattr(packet, 'http'):
                    print(f"Data (HTTP Example): {packet.http.get_field_by_showname('Full Request URI')}")
            
            # UDP protocol
            elif hasattr(packet, 'udp'):
                udp_pkt = packet.udp
                print(f"UDP Packet: Src Port: {udp_pkt.srcport}, Dest Port: {udp_pkt.dstport}")
                if hasattr(packet, 'dns'):
                    print(f"Data (DNS Example): {packet.dns.qry_name}")
            
            # ICMP protocol
            elif hasattr(packet, 'icmp'):
                icmp_pkt = packet.icmp
                print(f"ICMP Packet: Type: {icmp_pkt.type}, Code: {icmp_pkt.code}")

        elif hasattr(packet, 'ipv6'):
            ip_src = packet.ipv6.src
            ip_dst = packet.ipv6.dst
            print(f"Captured IPv6 Packet: Src IP: {ip_src}, Dest IP: {ip_dst}")

            # TCP protocol
            if hasattr(packet, 'tcp'):
                tcp_pkt = packet.tcp
                print(f"TCP Packet: Src Port: {tcp_pkt.srcport}, Dest Port: {tcp_pkt.dstport}")
                if hasattr(packet, 'http'):
                    print(f"Data (HTTP Example): {packet.http.get_field_by_showname('Full Request URI')}")
            
            # UDP protocol
            elif hasattr(packet, 'udp'):
                udp_pkt = packet.udp
                print(f"UDP Packet: Src Port: {udp_pkt.srcport}, Dest Port: {udp_pkt.dstport}")
                if hasattr(packet, 'dns'):
                    print(f"Data (DNS Example): {packet.dns.qry_name}")
            
            # ICMPv6 protocol
            elif hasattr(packet, 'icmpv6'):
                icmp_pkt = packet.icmpv6
                print(f"ICMPv6 Packet: Type: {icmp_pkt.type}, Code: {icmp_pkt.code}")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to start packet capture and sending packets
def capture_and_send(interface, target_ip, src_ip):
    try:
        # Start capturing packets using PyShark
        capture = pyshark.LiveCapture(interface=interface, bpf_filter='ip or ip6')

        # Start sending packets using Scapy
        send_thread = threading.Thread(target=send_packets, args=(src_ip, target_ip))
        send_thread.daemon = True
        send_thread.start()

        # Process captured packets
        for packet in capture.sniff_continuously():
            try:
                if hasattr(packet, 'ip') and (target_ip in (packet.ip.src, packet.ip.dst)):
                    process_packet(packet)
                elif hasattr(packet, 'ipv6') and (target_ip in (packet.ipv6.src, packet.ipv6.dst)):
                    process_packet(packet)
            except Exception as e:
                print(f"Error processing captured packet: {e}")

    except Exception as e:
        print(f"Error starting packet capture: {e}")

def main():
    # Set up command-line arguments
    parser = argparse.ArgumentParser(description='Capture and send packets using Scapy and PyShark.')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Network interface to use (e.g., eth0)')
    parser.add_argument('-t', '--target-ip', type=str, required=True, help='Target IP address to capture packets for')
    parser.add_argument('-s', '--source-ip', type=str, required=True, help='Source IP address for sending packets')

    args = parser.parse_args()

    interface = args.interface
    target_ip = args.target_ip
    source_ip = args.source_ip

    capture_and_send(interface, target_ip, source_ip)

if __name__ == "__main__":
    main()
